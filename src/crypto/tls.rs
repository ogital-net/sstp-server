//! Tokio-friendly TLS server using AWS-LC's `libssl`.
//!
//! The TCP socket fd is registered with `SSL_set_fd` so AES decryption
//! happens directly on the network buffer; userspace makes no extra copy
//! between TCP and TLS. `AsyncFd` provides readiness signalling; we never
//! call non-blocking syscalls ourselves — `libssl` does that under the
//! hood and we translate `WANT_READ` / `WANT_WRITE` into tokio polls.

use std::ffi::{CStr, c_int, c_void};
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use aws_lc_sys as aws;
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::ffi::{Ssl, SslCtx};

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("TLS init failed: {0}")]
    Init(String),
    #[error("TLS I/O: {0}")]
    Io(#[from] io::Error),
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
}

/// Shared TLS server context (`SSL_CTX`).
///
/// `SSL_CTX` is documented thread-safe in AWS-LC, so this can be cloned
/// freely across I/O workers. `Clone` uses `SSL_CTX_up_ref` to increment
/// the library-internal refcount; no extra `Arc` is needed.
#[derive(Clone)]
pub struct SslContext {
    inner: SslCtx,
}

impl SslContext {
    /// Build a TLS server context from a PEM certificate chain and key.
    pub fn server_from_pem(cert: &Path, key: &Path) -> Result<Self, TlsError> {
        // SAFETY: TLS_server_method returns a static SSL_METHOD; SSL_CTX_new
        // either returns a valid pointer or null on alloc failure.
        let ctx_ptr = unsafe { aws::SSL_CTX_new(aws::TLS_server_method()) };
        // SAFETY: ctx_ptr is the freshly-allocated SSL_CTX we just owned.
        let ctx = unsafe { SslCtx::from_raw(ctx_ptr) }
            .ok_or_else(|| TlsError::Init("SSL_CTX_new returned null".into()))?;

        // TLS 1.2 is the floor for SSTP. Windows clients support 1.2+;
        // 1.0/1.1 are deprecated. Value 771 fits in a u16 trivially.
        // SAFETY: ctx is valid; constants are well-known.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rc =
            unsafe { aws::SSL_CTX_set_min_proto_version(ctx.as_ptr(), aws::TLS1_2_VERSION as u16) };
        if rc != 1 {
            return Err(TlsError::Init(
                "SSL_CTX_set_min_proto_version failed".into(),
            ));
        }

        let cert_c = path_to_cstring(cert)?;
        let key_c = path_to_cstring(key)?;

        // SAFETY: ctx valid; cert_c is a NUL-terminated C string we own.
        let rc = unsafe { aws::SSL_CTX_use_certificate_chain_file(ctx.as_ptr(), cert_c.as_ptr()) };
        if rc != 1 {
            return Err(TlsError::Init(format!(
                "loading certificate chain from {}: {}",
                cert.display(),
                last_error()
            )));
        }

        // SAFETY: ctx valid; key_c is a NUL-terminated C string we own.
        let rc = unsafe {
            aws::SSL_CTX_use_PrivateKey_file(ctx.as_ptr(), key_c.as_ptr(), aws::SSL_FILETYPE_PEM)
        };
        if rc != 1 {
            return Err(TlsError::Init(format!(
                "loading private key from {}: {}",
                key.display(),
                last_error()
            )));
        }

        // SAFETY: ctx valid.
        let rc = unsafe { aws::SSL_CTX_check_private_key(ctx.as_ptr()) };
        if rc != 1 {
            return Err(TlsError::Init(format!(
                "private key does not match certificate: {}",
                last_error()
            )));
        }

        Ok(Self { inner: ctx })
    }

    /// Accept a TLS connection on an already-accepted TCP stream.
    pub async fn accept(&self, stream: TcpStream) -> Result<TlsStream, TlsError> {
        // SAFETY: SSL_new on a valid SSL_CTX returns a fresh SSL or null.
        let ssl_ptr = unsafe { aws::SSL_new(self.inner.as_ptr()) };
        // SAFETY: ssl_ptr is the freshly-allocated SSL we just owned.
        let ssl = unsafe { Ssl::from_raw(ssl_ptr) }
            .ok_or_else(|| TlsError::Handshake("SSL_new returned null".into()))?;

        // tokio's TcpStream is already registered with the runtime's epoll;
        // wrapping it in AsyncFd would re-register and fail with EEXIST.
        // Deregister by converting to a std stream first.
        let std_stream = stream.into_std()?;
        let fd = AsyncFd::new(std_stream)?;
        let raw = fd.get_ref().as_raw_fd();

        // SAFETY: ssl is valid; raw is the TcpStream's fd, owned by `fd`
        // and outlives the SSL handle (both stored in TlsStream).
        let rc = unsafe { aws::SSL_set_fd(ssl.as_ptr(), raw) };
        if rc != 1 {
            return Err(TlsError::Handshake("SSL_set_fd failed".into()));
        }
        // SAFETY: ssl is valid; no return value.
        unsafe { aws::SSL_set_accept_state(ssl.as_ptr()) };

        let mut s = TlsStream { fd, ssl };
        handshake(&mut s).await?;
        Ok(s)
    }
}

fn path_to_cstring(p: &Path) -> Result<std::ffi::CString, TlsError> {
    let bytes = p
        .to_str()
        .ok_or_else(|| TlsError::Init(format!("non-UTF-8 path: {}", p.display())))?
        .as_bytes();
    std::ffi::CString::new(bytes).map_err(|e| TlsError::Init(format!("path contains NUL: {e}")))
}

fn last_error() -> String {
    // Drain the AWS-LC error queue into a single string.
    let mut buf = [0u8; 256];
    // SAFETY: ERR_get_error has no arguments.
    let code = unsafe { aws::ERR_get_error() };
    if code == 0 {
        return "(no error queued)".into();
    }
    // SAFETY: buf describes a writable slice; ERR_error_string_n writes
    // a NUL-terminated string of at most `len` bytes.
    unsafe { aws::ERR_error_string_n(code, buf.as_mut_ptr().cast(), buf.len()) };
    // Drain any further entries to keep the queue clean.
    // SAFETY: ERR_clear_error has no arguments.
    unsafe { aws::ERR_clear_error() };
    let cstr = CStr::from_bytes_until_nul(&buf).unwrap_or(c"(malformed err)");
    cstr.to_string_lossy().into_owned()
}

/// Active TLS connection. Implements `AsyncRead` + `AsyncWrite`.
pub struct TlsStream {
    fd: AsyncFd<std::net::TcpStream>,
    ssl: Ssl,
}

impl TlsStream {
    /// RFC 5705 / TLS 1.3 §7.5 keying material exporter. Used by SSTP
    /// for CMK derivation when no inner-method MSK is available
    /// ([MS-SSTP] §3.2.5.2).
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        let (ctx_ptr, ctx_len, use_ctx) = match context {
            Some(c) => (c.as_ptr(), c.len(), 1),
            None => (std::ptr::null(), 0, 0),
        };
        // SAFETY: ssl is valid; out describes a writable slice; label is a
        // readable slice; ctx_ptr/ctx_len describe a readable slice or are
        // (null, 0) per `use_ctx == 0`.
        let rc = unsafe {
            aws::SSL_export_keying_material(
                self.ssl.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                label.as_ptr().cast(),
                label.len(),
                ctx_ptr,
                ctx_len,
                use_ctx,
            )
        };
        if rc == 1 {
            Ok(())
        } else {
            Err(TlsError::Handshake(format!(
                "SSL_export_keying_material failed: {}",
                last_error()
            )))
        }
    }
}

async fn handshake(s: &mut TlsStream) -> Result<(), TlsError> {
    loop {
        // SAFETY: ssl is valid.
        let r = unsafe { aws::SSL_do_handshake(s.ssl.as_ptr()) };
        if r == 1 {
            return Ok(());
        }
        // SAFETY: ssl is valid.
        let e = unsafe { aws::SSL_get_error(s.ssl.as_ptr(), r) };
        match e {
            aws::SSL_ERROR_WANT_READ => {
                s.fd.readable_mut().await?.clear_ready();
            }
            aws::SSL_ERROR_WANT_WRITE => {
                s.fd.writable_mut().await?.clear_ready();
            }
            _ => {
                return Err(TlsError::Handshake(format!(
                    "SSL_do_handshake: code={e}, {}",
                    last_error()
                )));
            }
        }
    }
}

fn ssl_io_err(e: c_int) -> io::Error {
    io::Error::other(format!("SSL error code {e}: {}", last_error()))
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = ready!(this.fd.poll_read_ready_mut(cx))?;
            // SAFETY: SSL_read writes initialised bytes into the returned
            // region; we mark them initialised below via `ReadBuf::assume_init`
            // before exposing them.
            let unfilled = unsafe { buf.unfilled_mut() };
            let cap = c_int::try_from(unfilled.len()).unwrap_or(c_int::MAX);
            // SAFETY: ssl is valid; unfilled describes a writable region of
            // at least `cap` bytes.
            let n = unsafe {
                aws::SSL_read(
                    this.ssl.as_ptr(),
                    unfilled.as_mut_ptr().cast::<c_void>(),
                    cap,
                )
            };
            if n > 0 {
                // n > 0 so the cast cannot lose the sign.
                #[allow(clippy::cast_sign_loss)]
                let n = n as usize;
                // SAFETY: SSL_read wrote n initialised bytes into the
                // unfilled region.
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            // SAFETY: ssl is valid.
            let e = unsafe { aws::SSL_get_error(this.ssl.as_ptr(), n) };
            match e {
                aws::SSL_ERROR_ZERO_RETURN => return Poll::Ready(Ok(())), // EOF
                aws::SSL_ERROR_WANT_READ => {
                    guard.clear_ready();
                }
                aws::SSL_ERROR_WANT_WRITE => {
                    drop(guard);
                    ready!(this.fd.poll_write_ready_mut(cx))?.clear_ready();
                }
                _ => return Poll::Ready(Err(ssl_io_err(e))),
            }
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        loop {
            let mut guard = ready!(this.fd.poll_write_ready_mut(cx))?;
            let cap = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
            // SAFETY: ssl is valid; data describes a readable slice of cap bytes.
            let n =
                unsafe { aws::SSL_write(this.ssl.as_ptr(), data.as_ptr().cast::<c_void>(), cap) };
            if n > 0 {
                // n > 0 so the cast is exact.
                #[allow(clippy::cast_sign_loss)]
                return Poll::Ready(Ok(n as usize));
            }
            // SAFETY: ssl is valid.
            let e = unsafe { aws::SSL_get_error(this.ssl.as_ptr(), n) };
            match e {
                aws::SSL_ERROR_WANT_WRITE => {
                    guard.clear_ready();
                }
                aws::SSL_ERROR_WANT_READ => {
                    drop(guard);
                    ready!(this.fd.poll_read_ready_mut(cx))?.clear_ready();
                }
                _ => return Poll::Ready(Err(ssl_io_err(e))),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // libssl writes go straight to the socket via SSL_set_fd; there's
        // no userspace buffer to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // SAFETY: ssl is valid.
            let r = unsafe { aws::SSL_shutdown(this.ssl.as_ptr()) };
            if r >= 0 {
                return Poll::Ready(Ok(()));
            }
            // SAFETY: ssl is valid.
            let e = unsafe { aws::SSL_get_error(this.ssl.as_ptr(), r) };
            match e {
                aws::SSL_ERROR_WANT_READ => {
                    ready!(this.fd.poll_read_ready_mut(cx))?.clear_ready();
                }
                aws::SSL_ERROR_WANT_WRITE => {
                    ready!(this.fd.poll_write_ready_mut(cx))?.clear_ready();
                }
                _ => return Poll::Ready(Err(ssl_io_err(e))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn gen_self_signed(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let status = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .args(["-days", "1", "-subj", "/CN=localhost"])
            .output()
            .expect("run openssl");
        assert!(status.status.success(), "openssl: {status:?}");
        (cert, key)
    }

    #[test]
    fn build_context_from_pem() {
        let tmp = tempdir();
        let (cert, key) = gen_self_signed(tmp.path());
        let _ctx = SslContext::server_from_pem(&cert, &key).expect("ctx");
    }

    #[test]
    fn missing_cert_returns_error() {
        let tmp = tempdir();
        let (_cert, key) = gen_self_signed(tmp.path());
        let bad = tmp.path().join("missing.pem");
        let res = SslContext::server_from_pem(&bad, &key);
        let Err(err) = res else {
            panic!("expected error")
        };
        assert!(matches!(err, TlsError::Init(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn handshake_read_write_export() {
        let tmp = tempdir();
        let (cert, key) = gen_self_signed(tmp.path());
        let ctx = SslContext::server_from_pem(&cert, &key).expect("ctx");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = ctx.accept(sock).await.expect("server accept");
            let mut buf = [0u8; 32];
            let n = tls.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello\n");
            tls.write_all(b"world\n").await.unwrap();
            let mut ekm = [0u8; 16];
            tls.export_keying_material(&mut ekm, b"SSTP-TEST", None)
                .unwrap();
            ekm
        });

        // openssl s_client as the peer.
        let mut child = tokio::process::Command::new("openssl")
            .args(["s_client", "-quiet", "-no_ign_eof", "-connect"])
            .arg(format!("127.0.0.1:{}", addr.port()))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn openssl s_client");

        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        stdin.write_all(b"hello\n").await.unwrap();
        stdin.flush().await.unwrap();

        let mut reply = [0u8; 16];
        let n = stdout.read(&mut reply).await.unwrap();
        assert!(reply[..n].starts_with(b"world"), "got {:?}", &reply[..n]);

        drop(stdin);
        let _ = child.wait().await;
        let ekm = server.await.unwrap();
        assert_ne!(ekm, [0u8; 16]);
    }

    fn tempdir() -> tempdir_lite::TempDir {
        tempdir_lite::TempDir::new("sstp-tls-test").expect("tempdir")
    }
}

#[cfg(test)]
mod tempdir_lite {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(prefix: &str) -> std::io::Result<Self> {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!("{prefix}-{nanos}"));
            std::fs::create_dir(&p)?;
            Ok(Self(p))
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
