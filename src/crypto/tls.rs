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
use super::hash::{Sha1, Sha256};

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
    /// SHA-1 of the leaf certificate's DER encoding. Required for
    /// clients (e.g. RouterOS 7) that select SHA-1 in the SSTP Crypto
    /// Binding attribute ([MS-SSTP] §2.2.7 / §3.2.5.2).
    cert_hash_sha1: [u8; 20],
    /// SHA-256 of the leaf certificate's DER encoding. Used as the
    /// server cert hash carried in the SSTP Crypto Binding attribute
    /// ([MS-SSTP] §2.2.7 / §3.2.5.2). Computed once at context build
    /// time; the cert never changes for the life of a context.
    cert_hash_sha256: [u8; 32],
}

impl SslContext {
    /// Build a TLS server context from a PEM certificate chain and key.
    ///
    /// When `aead_only` is true, the TLS 1.2 cipher list is restricted
    /// to AEAD suites (AES-GCM / ChaCha20-Poly1305) so every session
    /// is kTLS-eligible. Use this in `--data-path kernel` mode where
    /// CBC-SHA falls outside the kTLS allow-list and would force the
    /// session to fail at attach time anyway. Leave it false for
    /// permissive deployments (auto / tun / userspace) so legacy
    /// clients that only offer CBC suites can still connect; those
    /// sessions transparently fall back to userspace TLS.
    pub fn server_from_pem(cert: &Path, key: &Path, aead_only: bool) -> Result<Self, TlsError> {
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

        // Restrict the TLS 1.2 cipher list to AEAD suites (AES-GCM,
        // ChaCha20-Poly1305) only when the operator opted into the
        // kernel data path. kTLS only accelerates AEAD ciphers, so a
        // CBC-SHA suite (e.g. `AES256-SHA`) would force the data path
        // back to userspace; in `--data-path kernel` mode that's a
        // session-level failure (`SSTP_IOC_ATTACH: EOPNOTSUPP`), so
        // we'd rather refuse the handshake here with `NO_SHARED_CIPHER`.
        // TLS 1.3 only defines AEAD suites, so its ciphersuite list
        // never needs pruning. The list is OpenSSL/AWS-LC cipher-list
        // syntax, ECDHE-first for forward secrecy, then plain RSA-AEAD
        // as a fallback for clients that don't offer ECDHE.
        if aead_only {
            const TLS12_CIPHERS: &[u8] =
                b"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                  AES128-GCM-SHA256:AES256-GCM-SHA384\0";
            // SAFETY: ctx valid; TLS12_CIPHERS is a NUL-terminated byte string.
            let rc = unsafe {
                aws::SSL_CTX_set_cipher_list(ctx.as_ptr(), TLS12_CIPHERS.as_ptr().cast())
            };
            if rc != 1 {
                return Err(TlsError::Init(format!(
                    "SSL_CTX_set_cipher_list (TLS 1.2 AEAD-only): {}",
                    last_error()
                )));
            }
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

        // Disable the server-side session cache. AWS-LC guards the
        // cache (hashtable + LRU + stats counters) with a single
        // CRYPTO_MUTEX touched by every `SSL_new` / `SSL_free` /
        // handshake completion, which becomes the dominant cross-worker
        // contention point at high accept rates because all I/O workers
        // share one `SSL_CTX` via `SSL_CTX_up_ref`. We don't benefit
        // from the cache: TLS 1.3 (the modern path for Windows SSTP
        // clients) uses stateless tickets, and TLS 1.2 cache-based
        // resumption only helps repeat connections to the same worker
        // — SSTP tunnels are multi-hour, so resumption rate is
        // microscopic regardless.
        // SAFETY: ctx valid; SSL_SESS_CACHE_OFF is a well-known constant.
        unsafe {
            aws::SSL_CTX_set_session_cache_mode(ctx.as_ptr(), aws::SSL_SESS_CACHE_OFF);
        }

        // Disable post-handshake ticket emission for both TLS 1.3 and
        // TLS 1.2. Once kTLS is installed on the TCP socket the kernel
        // owns the record layer for both directions and rejects any
        // non-application_data record that userspace tries to write.
        // libssl's default for TLS 1.3 is to emit two NewSessionTicket
        // records shortly after the handshake completes, which is fine
        // if the tickets land before `install_ktls`, but a marginal
        // race against post-handshake state machine progress and
        // pointless given we already disable the session cache.
        // Forcing zero tickets and `SSL_OP_NO_TICKET` makes "no
        // post-handshake records originate from us" a structural
        // property, not a timing assumption — a hard prerequisite for
        // long-lived TLS 1.3 sessions on the kmod path.
        //
        // Renegotiation is already off by default in AWS-LC
        // (`SSL_OP_NO_RENEGOTIATION` is a no-op constant of 0); TLS 1.3
        // forbids it altogether. Together with `SSL_CTX_set_num_tickets(0)`
        // this leaves *client*-initiated `KeyUpdate` (RFC 8446 §4.6.3)
        // as the only remaining post-handshake record source. Windows
        // SSTP clients do not initiate it in practice; the kmod
        // detects it via `TLS_GET_RECORD_TYPE` and surfaces
        // `SSTP_EVT_TLS_REKEY_NEEDED` so userspace can tear the
        // session down cleanly (the client auto-reconnects).
        // SAFETY: ctx valid; constants are well-known.
        let rc = unsafe { aws::SSL_CTX_set_num_tickets(ctx.as_ptr(), 0) };
        if rc != 1 {
            return Err(TlsError::Init(format!(
                "SSL_CTX_set_num_tickets(0): {}",
                last_error()
            )));
        }
        // SAFETY: ctx valid; `SSL_OP_NO_TICKET` is `0x4000`. The return
        // value is the new option bitmask, which we don't need.
        unsafe {
            #[allow(clippy::cast_sign_loss)]
            aws::SSL_CTX_set_options(ctx.as_ptr(), aws::SSL_OP_NO_TICKET as u32);
        }

        // ALPN: select `http/1.1` if the client offers it, otherwise
        // omit the extension from our ServerHello (NOACK). SSTP
        // doesn't use ALPN itself, but Windows / some `sstpc` builds
        // send `http/1.1` in the ClientHello, and certain
        // load-balancers / IDS appliances drop sessions when the
        // server fails to echo a value the client offered. The cost
        // is a one-time static-buffer match per handshake; no per-
        // packet impact, no kTLS interaction.
        // SAFETY: ctx valid; `alpn_select_cb` has the signature aws-lc
        // expects; `arg` is unused by the callback.
        unsafe {
            aws::SSL_CTX_set_alpn_select_cb(
                ctx.as_ptr(),
                Some(alpn_select_cb),
                std::ptr::null_mut(),
            );
        }

        let cert_hash_sha256 = leaf_cert_hash_sha256(&ctx)?;
        let cert_hash_sha1 = leaf_cert_hash_sha1(&ctx)?;

        Ok(Self {
            inner: ctx,
            cert_hash_sha1,
            cert_hash_sha256,
        })
    }

    /// SHA-1 of the leaf certificate's DER encoding, for clients that
    /// select SHA-1 in the SSTP Crypto Binding ([MS-SSTP] §2.2.7).
    #[must_use]
    pub fn cert_hash_sha1(&self) -> [u8; 20] {
        self.cert_hash_sha1
    }

    /// SHA-256 of the leaf certificate's DER encoding, the value the
    /// server places in the SSTP Crypto Binding cert-hash field
    /// ([MS-SSTP] §2.2.7).
    #[must_use]
    pub fn cert_hash_sha256(&self) -> [u8; 32] {
        self.cert_hash_sha256
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

/// ALPN protocol list in wire format (length-prefixed): the single
/// protocol `http/1.1`. Static so the pointer handed back from the
/// selection callback stays valid for the lifetime of the process.
static ALPN_HTTP_1_1: [u8; 9] = *b"\x08http/1.1";

/// `SSL_CTX_set_alpn_select_cb` callback. If the client offered
/// `http/1.1` in its `ClientHello` ALPN extension, echo it back via
/// `SSL_select_next_proto`; otherwise return `SSL_TLSEXT_ERR_NOACK`
/// so libssl omits the extension from the `ServerHello` entirely
/// (the same wire result as not configuring ALPN at all).
unsafe extern "C" fn alpn_select_cb(
    _ssl: *mut aws::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    in_: *const u8,
    in_len: std::os::raw::c_uint,
    _arg: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    let mut chosen: *mut u8 = std::ptr::null_mut();
    let mut chosen_len: u8 = 0;
    // SAFETY: `in_`/`in_len` are libssl-supplied (peer ALPN list,
    // already length-validated by libssl); `ALPN_HTTP_1_1` is a
    // static byte slice with the documented length. The pointer
    // SSL_select_next_proto writes into `chosen` aliases either
    // `in_` or `ALPN_HTTP_1_1` — both remain valid for the rest
    // of the handshake, which is all libssl requires.
    let rc = unsafe {
        aws::SSL_select_next_proto(
            &raw mut chosen,
            &raw mut chosen_len,
            in_,
            in_len,
            ALPN_HTTP_1_1.as_ptr(),
            // ALPN_HTTP_1_1.len() == 9, fits in c_uint trivially.
            #[allow(clippy::cast_possible_truncation)]
            {
                ALPN_HTTP_1_1.len() as std::os::raw::c_uint
            },
        )
    };
    if rc == aws::OPENSSL_NPN_NEGOTIATED {
        // SAFETY: `out` / `out_len` are non-null per the
        // `SSL_CTX_set_alpn_select_cb` contract.
        unsafe {
            *out = chosen;
            *out_len = chosen_len;
        }
        aws::SSL_TLSEXT_ERR_OK
    } else {
        aws::SSL_TLSEXT_ERR_NOACK
    }
}

/// Compute SHA-256 of the leaf certificate's DER encoding for an
/// already-loaded `SSL_CTX`. Used to populate
/// [`SslContext::cert_hash_sha256`].
fn leaf_cert_hash_sha256(ctx: &SslCtx) -> Result<[u8; 32], TlsError> {
    let der = leaf_cert_der(ctx)?;
    Ok(Sha256::digest(&der))
}

/// Compute SHA-1 of the leaf certificate's DER encoding for an
/// already-loaded `SSL_CTX`. Required for clients (e.g. RouterOS 7)
/// that select SHA-1 in the SSTP Crypto Binding attribute.
fn leaf_cert_hash_sha1(ctx: &SslCtx) -> Result<[u8; 20], TlsError> {
    let der = leaf_cert_der(ctx)?;
    Ok(Sha1::digest(&der))
}

/// DER-encode the leaf certificate from an already-loaded `SSL_CTX`.
fn leaf_cert_der(ctx: &SslCtx) -> Result<Vec<u8>, TlsError> {
    // SAFETY: ctx is a valid SSL_CTX with a cert loaded; the returned
    // pointer is borrowed (no _free required) per AWS-LC docs.
    let x509 = unsafe { aws::SSL_CTX_get0_certificate(ctx.as_ptr()) };
    if x509.is_null() {
        return Err(TlsError::Init(
            "SSL_CTX_get0_certificate returned null".into(),
        ));
    }
    // Two-call pattern: pass a null `outp` to learn the length, then
    // a real buffer to receive the bytes. AWS-LC writes the DER bytes
    // and advances `outp` past the end, so we hold an `original`
    // pointer to recover the start of the buffer.
    // SAFETY: x509 is valid; passing `null` as outp asks for length only.
    let len = unsafe { aws::i2d_X509(x509, std::ptr::null_mut()) };
    if len <= 0 {
        return Err(TlsError::Init(format!(
            "i2d_X509 length probe failed: {}",
            last_error()
        )));
    }
    // `len` is `c_int`, validated positive above; usize conversion is sound.
    #[allow(clippy::cast_sign_loss)]
    let mut der = vec![0u8; len as usize];
    let mut out_ptr = der.as_mut_ptr();
    // SAFETY: x509 is valid; out_ptr points to a writable buffer of
    // `len` bytes; AWS-LC advances `*outp` past the end on success.
    let written = unsafe { aws::i2d_X509(x509, &raw mut out_ptr) };
    if written != len {
        return Err(TlsError::Init(format!(
            "i2d_X509 wrote {written} bytes, expected {len}"
        )));
    }
    Ok(der)
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

/// Negotiated TLS parameters relevant to deciding whether we should
/// attempt the SSTP kernel data path for this session.
#[derive(Debug, Clone)]
pub struct KtlsEligibility {
    pub compatible: bool,
    pub tls_version: String,
    pub cipher: String,
}

impl KtlsEligibility {
    fn unknown() -> Self {
        Self {
            compatible: false,
            tls_version: "unknown".into(),
            cipher: "unknown".into(),
        }
    }
}

impl TlsStream {
    /// Borrow the underlying TCP fd. Required by the SSTP kernel
    /// module's `SSTP_IOC_ATTACH` ioctl: the kmod takes ownership of
    /// the kernel-side socket and runs the steady-state SSTP/kTLS
    /// path itself. Userspace continues to hold its `TcpStream` for
    /// the control path until the data path is fully cut over.
    pub fn tcp_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.fd.get_ref().as_fd()
    }

    /// Return whether the negotiated TLS session parameters are a
    /// reasonable kTLS candidate for the in-tree SSTP kernel module.
    ///
    /// Allow-list: AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305
    /// over TLS 1.2 / 1.3 — every AEAD a Windows or sstpc client
    /// negotiates in the field. Sessions outside this set stay on
    /// the userspace data path even when `/dev/sstp` is present.
    #[must_use]
    pub fn ktls_eligibility(&self) -> KtlsEligibility {
        // SAFETY: ssl is valid for the life of this TlsStream.
        let cipher = unsafe { aws::SSL_get_current_cipher(self.ssl.as_ptr()) };
        if cipher.is_null() {
            return KtlsEligibility::unknown();
        }

        // SAFETY: non-null `cipher` comes from libssl; name pointer is
        // NUL-terminated and borrowed for the lifetime of the cipher.
        let cipher_name = unsafe {
            CStr::from_ptr(aws::SSL_CIPHER_get_name(cipher))
                .to_string_lossy()
                .into_owned()
        };

        // SAFETY: ssl is valid; SSL_get_version returns a borrowed
        // NUL-terminated string such as "TLSv1.3".
        let version_name = unsafe {
            let p = aws::SSL_get_version(self.ssl.as_ptr());
            if p.is_null() {
                "unknown".into()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };

        let compatible = matches!(version_name.as_str(), "TLSv1.2" | "TLSv1.3")
            && matches!(
                cipher_name.as_str(),
                "TLS_AES_128_GCM_SHA256"
                    | "TLS_AES_256_GCM_SHA384"
                    | "TLS_CHACHA20_POLY1305_SHA256"
                    | "ECDHE-RSA-AES128-GCM-SHA256"
                    | "ECDHE-RSA-AES256-GCM-SHA384"
                    | "ECDHE-RSA-CHACHA20-POLY1305"
                    | "ECDHE-ECDSA-AES128-GCM-SHA256"
                    | "ECDHE-ECDSA-AES256-GCM-SHA384"
                    | "ECDHE-ECDSA-CHACHA20-POLY1305"
                    | "AES128-GCM-SHA256"
                    | "AES256-GCM-SHA384"
            );

        KtlsEligibility {
            compatible,
            tls_version: version_name,
            cipher: cipher_name,
        }
    }

    /// Queue a TLS 1.3 `KeyUpdate` post-handshake message
    /// ([RFC 8446] §4.6.3). The message is emitted on the next
    /// `SSL_write` (i.e. the next outbound SSTP frame); after that
    /// our send keys roll. If `request_peer` is `true`, we set the
    /// `update_requested` flag and the peer is required to respond
    /// with its own `KeyUpdate` before sending more application
    /// data — that's what exercises the receive-side rekey path.
    ///
    /// Only meaningful before the kmod takes ownership of the
    /// socket: once kTLS is installed and the kmod's session fd is
    /// driving the steady-state path, `aws-lc` is no longer the
    /// thing producing TLS records on this socket. The session
    /// driver enforces that gate; this method itself is unaware
    /// of the data-path mode.
    ///
    /// TLS 1.3 only. Returns `TlsError::Io` for the underlying
    /// libssl failure; callers should treat it as fatal at the
    /// session level (the SSL state may be desynchronised).
    pub fn request_key_update(&mut self, request_peer: bool) -> Result<(), TlsError> {
        let req = if request_peer {
            aws::SSL_KEY_UPDATE_REQUESTED
        } else {
            aws::SSL_KEY_UPDATE_NOT_REQUESTED
        };
        // SAFETY: ssl is valid for the life of this TlsStream;
        // SSL_key_update is documented to accept any TLS 1.3
        // server SSL after handshake completion, return 1 on
        // success, and queue the record for emission on the next
        // write. It is a no-op (returns 0) on TLS 1.2 connections.
        let rc = unsafe { aws::SSL_key_update(self.ssl.as_ptr(), req) };
        if rc == 1 {
            Ok(())
        } else {
            Err(TlsError::Io(std::io::Error::other(format!(
                "SSL_key_update returned {rc}"
            ))))
        }
    }

    /// RFC 5705 / TLS 1.3 §7.5 keying material exporter. Used by SSTP
    /// for CMK derivation when no inner-method MSK is available
    /// ([MS-SSTP] §3.2.5.2).
    #[allow(dead_code)] // FUTURE: wired by the Crypto Binding HLAK path once non-PAP auth methods land.
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

    /// Install kernel-TLS state on the underlying TCP socket using
    /// the just-negotiated TLS session keys.
    ///
    /// Must be called *after* the handshake completes and *before*
    /// any post-handshake `read`/`write` activity (the kernel takes
    /// over record framing for both directions, so any cleartext
    /// already buffered in `libssl` would be missed by the kernel).
    ///
    /// Supports AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305
    /// over either TLS 1.2 (`ECDHE-{RSA,ECDSA}-*` and the bare
    /// AES-GCM RSA suites) or TLS 1.3 (`TLS_AES_128_GCM_SHA256`,
    /// `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
    /// Other ciphers return `TlsError::Init(...)`; the caller
    /// should fall back to the userspace data path.
    pub fn install_ktls(&self) -> Result<(), TlsError> {
        use super::ktls;

        // SAFETY: ssl is valid for the life of this TlsStream.
        let cipher = unsafe { aws::SSL_get_current_cipher(self.ssl.as_ptr()) };
        if cipher.is_null() {
            return Err(TlsError::Init("no cipher negotiated".into()));
        }
        // SAFETY: non-null cipher; name pointer is borrowed for the
        // cipher's lifetime which exceeds this call.
        let cipher_name = unsafe { CStr::from_ptr(aws::SSL_CIPHER_get_name(cipher)) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: ssl is valid; SSL_get_version returns a borrowed
        // NUL-terminated string.
        let version_name = unsafe {
            let p = aws::SSL_get_version(self.ssl.as_ptr());
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };

        let (tx, rx) = match (version_name.as_str(), cipher_name.as_str()) {
            ("TLSv1.3", "TLS_AES_128_GCM_SHA256") => self.derive_tls13_aes128_gcm()?,
            (
                "TLSv1.2",
                "ECDHE-RSA-AES128-GCM-SHA256"
                | "ECDHE-ECDSA-AES128-GCM-SHA256"
                | "AES128-GCM-SHA256",
            ) => self.derive_tls12_aes128_gcm()?,
            ("TLSv1.3", "TLS_AES_256_GCM_SHA384") => {
                let (tx, rx) = self.derive_tls13_aes256_gcm()?;
                return ktls::install_aes_gcm_256(self.tcp_fd(), tx, rx)
                    .map_err(|e| TlsError::Init(format!("kTLS setsockopt: {e}")));
            }
            (
                "TLSv1.2",
                "ECDHE-RSA-AES256-GCM-SHA384"
                | "ECDHE-ECDSA-AES256-GCM-SHA384"
                | "AES256-GCM-SHA384",
            ) => {
                let (tx, rx) = self.derive_tls12_aes256_gcm()?;
                return ktls::install_aes_gcm_256(self.tcp_fd(), tx, rx)
                    .map_err(|e| TlsError::Init(format!("kTLS setsockopt: {e}")));
            }
            ("TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256") => {
                let (tx, rx) = self.derive_tls13_chacha20_poly1305()?;
                return ktls::install_chacha20_poly1305(self.tcp_fd(), tx, rx)
                    .map_err(|e| TlsError::Init(format!("kTLS setsockopt: {e}")));
            }
            ("TLSv1.2", "ECDHE-RSA-CHACHA20-POLY1305" | "ECDHE-ECDSA-CHACHA20-POLY1305") => {
                let (tx, rx) = self.derive_tls12_chacha20_poly1305()?;
                return ktls::install_chacha20_poly1305(self.tcp_fd(), tx, rx)
                    .map_err(|e| TlsError::Init(format!("kTLS setsockopt: {e}")));
            }
            _ => {
                return Err(TlsError::Init(format!(
                    "kTLS unsupported: {version_name} / {cipher_name}"
                )));
            }
        };

        ktls::install_aes_gcm_128(self.tcp_fd(), tx, rx)
            .map_err(|e| TlsError::Init(format!("kTLS setsockopt: {e}")))?;
        Ok(())
    }

    /// Derive TX/RX `tls12_crypto_info_aes_gcm_128` for a TLS 1.3
    /// `TLS_AES_128_GCM_SHA256` session.
    ///
    /// TLS 1.3 (RFC 8446 §7.3) gives us per-direction traffic
    /// secrets; we expand them via HKDF-Expand-Label into the
    /// 16-byte key and 12-byte static IV the AEAD needs. The
    /// kernel layout splits that IV into `salt[4] || iv[8]` and
    /// XORs the record sequence number into the low 8 bytes
    /// per §5.3.
    fn derive_tls13_aes128_gcm(
        &self,
    ) -> Result<
        (
            super::ktls::TlsCryptoInfoAesGcm128,
            super::ktls::TlsCryptoInfoAesGcm128,
        ),
        TlsError,
    > {
        use super::ktls;

        let write_secret = self.tls13_traffic_secret(Direction::Write, 32)?;
        let read_secret = self.tls13_traffic_secret(Direction::Read, 32)?;

        let write_key = ktls::hkdf_expand_label_sha256(&write_secret, "key", 16);
        let write_iv = ktls::hkdf_expand_label_sha256(&write_secret, "iv", 12);
        let read_key = ktls::hkdf_expand_label_sha256(&read_secret, "key", 16);
        let read_iv = ktls::hkdf_expand_label_sha256(&read_secret, "iv", 12);

        // SAFETY: ssl is valid; these accessors are pure reads of
        // the per-direction record counter and return a u64.
        let write_seq = unsafe { aws::SSL_get_write_sequence(self.ssl.as_ptr()) };
        let read_seq = unsafe { aws::SSL_get_read_sequence(self.ssl.as_ptr()) };

        Ok((
            build_aes_gcm_128(
                ktls::TLS_1_3_VERSION,
                &write_key,
                &write_iv[..4],
                &write_iv[4..12],
                write_seq,
            ),
            build_aes_gcm_128(
                ktls::TLS_1_3_VERSION,
                &read_key,
                &read_iv[..4],
                &read_iv[4..12],
                read_seq,
            ),
        ))
    }

    /// Derive TX/RX `tls12_crypto_info_aes_gcm_128` for a TLS 1.2
    /// AES-128-GCM session.
    ///
    /// TLS 1.2 (RFC 5246 §6.3, RFC 5288 §3) builds the key
    /// material from a single PRF block:
    ///
    /// ```text
    /// key_block = PRF(master_secret, "key expansion",
    ///                 server_random || client_random,
    ///                 key_block_len)
    /// ```
    ///
    /// For an AEAD cipher with no MAC key, the block is laid out
    /// as `client_write_key | server_write_key | client_write_IV
    /// | server_write_IV` where `*_IV` is the 4-byte implicit
    /// nonce (salt). Server-side, we send with `server_*` and
    /// receive with `client_*`.
    ///
    /// The 8-byte explicit nonce / `iv` field of the kTLS UAPI is
    /// seeded with the current record sequence number — the
    /// kernel uses it as the next record's `nonce_explicit` and
    /// then increments per RFC 5288 §3.
    fn derive_tls12_aes128_gcm(
        &self,
    ) -> Result<
        (
            super::ktls::TlsCryptoInfoAesGcm128,
            super::ktls::TlsCryptoInfoAesGcm128,
        ),
        TlsError,
    > {
        use super::ktls;

        // 2 * (key 16 + salt 4) = 40.
        const KEY_BLOCK_LEN: usize = 40;
        let mut block = [0u8; KEY_BLOCK_LEN];
        // SAFETY: ssl is valid; `block` is a writable buffer of
        // exactly `KEY_BLOCK_LEN` bytes; `SSL_generate_key_block`
        // writes `out_len` bytes to it on success.
        let rc = unsafe {
            aws::SSL_generate_key_block(self.ssl.as_ptr(), block.as_mut_ptr(), block.len())
        };
        if rc != 1 {
            return Err(TlsError::Init(format!(
                "SSL_generate_key_block: rc={rc}, {}",
                last_error()
            )));
        }

        let (client_key, rest) = block.split_at(16);
        let (server_key, rest) = rest.split_at(16);
        let (client_salt, server_salt) = rest.split_at(4);

        // SAFETY: ssl is valid; these accessors are pure reads
        // returning u64.
        let write_seq = unsafe { aws::SSL_get_write_sequence(self.ssl.as_ptr()) };
        let read_seq = unsafe { aws::SSL_get_read_sequence(self.ssl.as_ptr()) };

        Ok((
            build_aes_gcm_128(
                ktls::TLS_1_2_VERSION,
                server_key,
                server_salt,
                &write_seq.to_be_bytes(),
                write_seq,
            ),
            build_aes_gcm_128(
                ktls::TLS_1_2_VERSION,
                client_key,
                client_salt,
                &read_seq.to_be_bytes(),
                read_seq,
            ),
        ))
    }

    /// TLS 1.3 `TLS_AES_256_GCM_SHA384` sibling of
    /// [`derive_tls13_aes128_gcm`]. Traffic secrets are 48 bytes
    /// (SHA-384 output); the AEAD key is 32 bytes and the static
    /// IV is 12 bytes (split into `salt[4] || iv[8]` per the
    /// kernel UAPI).
    fn derive_tls13_aes256_gcm(
        &self,
    ) -> Result<
        (
            super::ktls::TlsCryptoInfoAesGcm256,
            super::ktls::TlsCryptoInfoAesGcm256,
        ),
        TlsError,
    > {
        use super::ktls;

        let write_secret = self.tls13_traffic_secret(Direction::Write, 48)?;
        let read_secret = self.tls13_traffic_secret(Direction::Read, 48)?;

        let write_key = ktls::hkdf_expand_label_sha384(&write_secret, "key", 32);
        let write_iv = ktls::hkdf_expand_label_sha384(&write_secret, "iv", 12);
        let read_key = ktls::hkdf_expand_label_sha384(&read_secret, "key", 32);
        let read_iv = ktls::hkdf_expand_label_sha384(&read_secret, "iv", 12);

        // SAFETY: ssl is valid; these accessors are pure reads of
        // the per-direction record counter and return a u64.
        let write_seq = unsafe { aws::SSL_get_write_sequence(self.ssl.as_ptr()) };
        let read_seq = unsafe { aws::SSL_get_read_sequence(self.ssl.as_ptr()) };

        Ok((
            build_aes_gcm_256(
                ktls::TLS_1_3_VERSION,
                &write_key,
                &write_iv[..4],
                &write_iv[4..12],
                write_seq,
            ),
            build_aes_gcm_256(
                ktls::TLS_1_3_VERSION,
                &read_key,
                &read_iv[..4],
                &read_iv[4..12],
                read_seq,
            ),
        ))
    }

    /// TLS 1.2 AES-256-GCM sibling of
    /// [`derive_tls12_aes128_gcm`]. The key block is laid out
    /// `client_write_key(32) | server_write_key(32) |
    /// client_write_IV(4) | server_write_IV(4)` = 72 bytes.
    fn derive_tls12_aes256_gcm(
        &self,
    ) -> Result<
        (
            super::ktls::TlsCryptoInfoAesGcm256,
            super::ktls::TlsCryptoInfoAesGcm256,
        ),
        TlsError,
    > {
        use super::ktls;

        // 2 * (key 32 + salt 4) = 72.
        const KEY_BLOCK_LEN: usize = 72;
        let mut block = [0u8; KEY_BLOCK_LEN];
        // SAFETY: ssl is valid; `block` is a writable buffer of
        // exactly `KEY_BLOCK_LEN` bytes; `SSL_generate_key_block`
        // writes `out_len` bytes to it on success.
        let rc = unsafe {
            aws::SSL_generate_key_block(self.ssl.as_ptr(), block.as_mut_ptr(), block.len())
        };
        if rc != 1 {
            return Err(TlsError::Init(format!(
                "SSL_generate_key_block: rc={rc}, {}",
                last_error()
            )));
        }

        let (client_key, rest) = block.split_at(32);
        let (server_key, rest) = rest.split_at(32);
        let (client_salt, server_salt) = rest.split_at(4);

        // SAFETY: ssl is valid; these accessors are pure reads
        // returning u64.
        let write_seq = unsafe { aws::SSL_get_write_sequence(self.ssl.as_ptr()) };
        let read_seq = unsafe { aws::SSL_get_read_sequence(self.ssl.as_ptr()) };

        Ok((
            build_aes_gcm_256(
                ktls::TLS_1_2_VERSION,
                server_key,
                server_salt,
                &write_seq.to_be_bytes(),
                write_seq,
            ),
            build_aes_gcm_256(
                ktls::TLS_1_2_VERSION,
                client_key,
                client_salt,
                &read_seq.to_be_bytes(),
                read_seq,
            ),
        ))
    }

    /// Derive TX/RX `tls12_crypto_info_chacha20_poly1305` for a
    /// TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` session.
    ///
    /// Same HKDF-Expand-Label expansion as
    /// [`derive_tls13_aes128_gcm`] (RFC 8446 §7.3 — both TLS 1.3
    /// AEADs hash with SHA-256), but the AEAD key is 32 bytes and
    /// the entire 12-byte static IV lives in `iv` (RFC 7905 / RFC
    /// 8446: ChaCha20-Poly1305 has no implicit-nonce / explicit-
    /// nonce split). The kernel layout reflects that with a
    /// zero-length salt; the kernel XORs the record sequence
    /// number into the low 8 bytes of `iv` per RFC 7905 §2.
    fn derive_tls13_chacha20_poly1305(
        &self,
    ) -> Result<
        (
            super::ktls::TlsCryptoInfoChacha20Poly1305,
            super::ktls::TlsCryptoInfoChacha20Poly1305,
        ),
        TlsError,
    > {
        use super::ktls;

        let write_secret = self.tls13_traffic_secret(Direction::Write, 32)?;
        let read_secret = self.tls13_traffic_secret(Direction::Read, 32)?;

        let write_key = ktls::hkdf_expand_label_sha256(&write_secret, "key", 32);
        let write_iv = ktls::hkdf_expand_label_sha256(&write_secret, "iv", 12);
        let read_key = ktls::hkdf_expand_label_sha256(&read_secret, "key", 32);
        let read_iv = ktls::hkdf_expand_label_sha256(&read_secret, "iv", 12);

        // SAFETY: ssl is valid; pure record-counter reads.
        let write_seq = unsafe { aws::SSL_get_write_sequence(self.ssl.as_ptr()) };
        let read_seq = unsafe { aws::SSL_get_read_sequence(self.ssl.as_ptr()) };

        Ok((
            build_chacha20_poly1305(ktls::TLS_1_3_VERSION, &write_key, &write_iv, write_seq),
            build_chacha20_poly1305(ktls::TLS_1_3_VERSION, &read_key, &read_iv, read_seq),
        ))
    }

    /// Derive TX/RX `tls12_crypto_info_chacha20_poly1305` for a
    /// TLS 1.2 `ECDHE-*-CHACHA20-POLY1305` session.
    ///
    /// Per RFC 7905 §2 the key block is laid out
    /// `client_write_key(32) | server_write_key(32) |
    /// client_write_iv(12) | server_write_iv(12)` = 88 bytes.
    /// There is no implicit/explicit nonce split: the per-record
    /// nonce is `padded_seq XOR write_iv`, computed by the kernel
    /// from `iv` plus the running `rec_seq`.
    fn derive_tls12_chacha20_poly1305(
        &self,
    ) -> Result<
        (
            super::ktls::TlsCryptoInfoChacha20Poly1305,
            super::ktls::TlsCryptoInfoChacha20Poly1305,
        ),
        TlsError,
    > {
        use super::ktls;

        // 2 * (key 32 + iv 12) = 88.
        const KEY_BLOCK_LEN: usize = 88;
        let mut block = [0u8; KEY_BLOCK_LEN];
        // SAFETY: ssl is valid; `block` is a writable buffer of
        // exactly `KEY_BLOCK_LEN` bytes.
        let rc = unsafe {
            aws::SSL_generate_key_block(self.ssl.as_ptr(), block.as_mut_ptr(), block.len())
        };
        if rc != 1 {
            return Err(TlsError::Init(format!(
                "SSL_generate_key_block: rc={rc}, {}",
                last_error()
            )));
        }

        let (client_key, rest) = block.split_at(32);
        let (server_key, rest) = rest.split_at(32);
        let (client_iv, server_iv) = rest.split_at(12);

        // SAFETY: ssl is valid; pure u64 reads.
        let write_seq = unsafe { aws::SSL_get_write_sequence(self.ssl.as_ptr()) };
        let read_seq = unsafe { aws::SSL_get_read_sequence(self.ssl.as_ptr()) };

        Ok((
            build_chacha20_poly1305(ktls::TLS_1_2_VERSION, server_key, server_iv, write_seq),
            build_chacha20_poly1305(ktls::TLS_1_2_VERSION, client_key, client_iv, read_seq),
        ))
    }

    /// Pull a TLS 1.3 traffic secret of the given length (in
    /// bytes) from libssl. Errors out on length mismatch — the
    /// caller pins the size against the negotiated hash.
    fn tls13_traffic_secret(
        &self,
        dir: Direction,
        expected_len: usize,
    ) -> Result<Vec<u8>, TlsError> {
        let mut buf = vec![0u8; 48]; // SHA-384 max
        let mut got = buf.len();
        // SAFETY: ssl is valid; buf + got point at owned storage
        // of sufficient size.
        let rc = unsafe {
            match dir {
                Direction::Write => aws::SSL_get_write_traffic_secret(
                    self.ssl.as_ptr(),
                    buf.as_mut_ptr(),
                    &raw mut got,
                ),
                Direction::Read => aws::SSL_get_read_traffic_secret(
                    self.ssl.as_ptr(),
                    buf.as_mut_ptr(),
                    &raw mut got,
                ),
            }
        };
        if rc != 1 || got != expected_len {
            return Err(TlsError::Init(format!(
                "SSL_get_{dir:?}_traffic_secret: rc={rc} len={got} want={expected_len}"
            )));
        }
        buf.truncate(got);
        Ok(buf)
    }
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Write,
    Read,
}

/// Assemble a `tls12_crypto_info_aes_gcm_128` from the pieces. The
/// `iv` field is the 8-byte initial explicit nonce; `salt` is the
/// 4-byte implicit nonce (TLS 1.2) / high half of the static IV
/// (TLS 1.3). `rec_seq` seeds the kernel's record counter.
fn build_aes_gcm_128(
    version: u16,
    key: &[u8],
    salt: &[u8],
    iv: &[u8],
    rec_seq: u64,
) -> crate::crypto::ktls::TlsCryptoInfoAesGcm128 {
    use crate::crypto::ktls;
    let mut out = ktls::TlsCryptoInfoAesGcm128 {
        info: ktls::TlsCryptoInfo {
            version,
            cipher_type: ktls::TLS_CIPHER_AES_GCM_128,
        },
        iv: [0; 8],
        key: [0; 16],
        salt: [0; 4],
        rec_seq: rec_seq.to_be_bytes(),
    };
    out.key.copy_from_slice(key);
    out.salt.copy_from_slice(salt);
    out.iv.copy_from_slice(iv);
    out
}

/// AES-256-GCM sibling of [`build_aes_gcm_128`]. Same `iv` / `salt`
/// / `rec_seq` semantics; only the key width changes.
fn build_aes_gcm_256(
    version: u16,
    key: &[u8],
    salt: &[u8],
    iv: &[u8],
    rec_seq: u64,
) -> crate::crypto::ktls::TlsCryptoInfoAesGcm256 {
    use crate::crypto::ktls;
    let mut out = ktls::TlsCryptoInfoAesGcm256 {
        info: ktls::TlsCryptoInfo {
            version,
            cipher_type: ktls::TLS_CIPHER_AES_GCM_256,
        },
        iv: [0; 8],
        key: [0; 32],
        salt: [0; 4],
        rec_seq: rec_seq.to_be_bytes(),
    };
    out.key.copy_from_slice(key);
    out.salt.copy_from_slice(salt);
    out.iv.copy_from_slice(iv);
    out
}

/// ChaCha20-Poly1305 sibling of [`build_aes_gcm_128`]. RFC 7905
/// gives no implicit/explicit nonce split, so the entire 12-byte
/// per-direction `write_iv` lives in `iv` and `salt` is empty.
/// `rec_seq` seeds the kernel's record counter, which it XORs into
/// the low 8 bytes of `iv` to form each AEAD nonce.
fn build_chacha20_poly1305(
    version: u16,
    key: &[u8],
    iv: &[u8],
    rec_seq: u64,
) -> crate::crypto::ktls::TlsCryptoInfoChacha20Poly1305 {
    use crate::crypto::ktls;
    let mut out = ktls::TlsCryptoInfoChacha20Poly1305 {
        info: ktls::TlsCryptoInfo {
            version,
            cipher_type: ktls::TLS_CIPHER_CHACHA20_POLY1305,
        },
        iv: [0; ktls::CHACHA20_POLY1305_IV_LEN],
        key: [0; ktls::CHACHA20_POLY1305_KEY_LEN],
        salt: [0; ktls::CHACHA20_POLY1305_SALT_LEN],
        rec_seq: rec_seq.to_be_bytes(),
    };
    out.key.copy_from_slice(key);
    out.iv.copy_from_slice(iv);
    out
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
        let _ctx = SslContext::server_from_pem(&cert, &key, false).expect("ctx");
    }

    /// The kmod data path requires no server-originated post-handshake
    /// records (`NewSessionTicket` included), since `kTLS_TX` rejects any
    /// non-`application_data` write. Lock that property in: a freshly
    /// built context must report `SSL_CTX_get_num_tickets() == 0`.
    /// Regression coverage for long-lived TLS 1.3 sessions on the
    /// kmod path.
    #[test]
    fn server_context_emits_no_session_tickets() {
        let tmp = tempdir();
        let (cert, key) = gen_self_signed(tmp.path());
        let ctx = SslContext::server_from_pem(&cert, &key, false).expect("ctx");
        // SAFETY: ctx.inner is a live SSL_CTX for the duration of this scope.
        let n = unsafe { aws::SSL_CTX_get_num_tickets(ctx.inner.as_ptr()) };
        assert_eq!(n, 0, "expected zero post-handshake tickets, got {n}");
    }

    #[test]
    fn missing_cert_returns_error() {
        let tmp = tempdir();
        let (_cert, key) = gen_self_signed(tmp.path());
        let bad = tmp.path().join("missing.pem");
        let res = SslContext::server_from_pem(&bad, &key, false);
        let Err(err) = res else {
            panic!("expected error")
        };
        assert!(matches!(err, TlsError::Init(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn handshake_read_write_export() {
        let tmp = tempdir();
        let (cert, key) = gen_self_signed(tmp.path());
        let ctx = SslContext::server_from_pem(&cert, &key, false).expect("ctx");

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
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::{SystemTime, UNIX_EPOCH};
            // Nanos alone collide when two tests start in the same
            // tick on a fast machine; combine with a per-process
            // monotonic counter to get a unique suffix.
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}-{n}"));
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
