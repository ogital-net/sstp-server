//! Safe Rust wrapper for the SSTP kernel module (`/dev/sstp`).
//!
//! Mirrors `kernel-abi/sstp.h`. The wrapper exposes:
//!
//! - [`probe`] — cheap availability check (does `/dev/sstp` open?).
//! - [`KmodSession::attach`] — hand the kernel a kTLS-equipped TCP fd
//!   plus a PPP unit and receive a session fd whose lifetime owns the
//!   kernel-side data path.
//! - [`KmodSession::chan_index`] / [`KmodSession::stats`] / poll on
//!   the session fd via [`KmodSession::as_fd`] for events.
//!
//! Closing the session fd (drop) detaches the channel and releases the
//! kernel-side references. The TCP fd reference is held by the kernel
//! independently — userspace may close its dup freely after attach.
//!
//! See `kmod/README.md` for the kernel side and `kmod/tests/test_sstp.c`
//! for a parallel C-language harness.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use super::ioctl::{ioc_read, ioc_readwrite, ioc_write};

const DEV_SSTP: &CStr = c"/dev/sstp";

// ---------------------------------------------------------------------------
// UAPI mirrored from kernel-abi/sstp.h. The repo's CI test
// `ioctl_numbers_match_kernel` in `super::ioctl` already validates that
// our `_IOC` ports produce kernel-equivalent request numbers; the same
// helpers compute the SSTP requests here, so the values are correct by
// construction.
// ---------------------------------------------------------------------------

/// `SSTP_ABI_VERSION_MAJOR` — kernel rejects mismatched majors.
pub const SSTP_ABI_VERSION_MAJOR: u16 = 0;
/// `SSTP_ABI_VERSION_MINOR`.
pub const SSTP_ABI_VERSION_MINOR: u16 = 1;

/// PFC negotiated.
pub const SSTP_F_PFC: u32 = 1 << 0;
/// ACFC negotiated.
pub const SSTP_F_ACFC: u32 = 1 << 1;
/// `IPv6CP` negotiated.
pub const SSTP_F_IPV6: u32 = 1 << 2;

const SSTP_IOC_MAGIC: u8 = b'S';

const SSTP_IOC_ATTACH: libc::c_ulong = ioc_readwrite::<SstpAttachRaw>(SSTP_IOC_MAGIC, 0x80);
const SSTP_IOC_DETACH: libc::c_ulong = ioc_write::<SstpDetachRaw>(SSTP_IOC_MAGIC, 0x81);
const SSTP_IOC_GETSTATS: libc::c_ulong = ioc_read::<SstpStats>(SSTP_IOC_MAGIC, 0x82);
const SSTP_IOC_GET_CHAN_INDEX: libc::c_ulong = ioc_read::<libc::c_int>(SSTP_IOC_MAGIC, 0x83);

/// Wire-compatible mirror of `struct sstp_attach`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SstpAttachRaw {
    abi_major: u16,
    abi_minor: u16,
    tcp_fd: i32,
    ppp_unit: i32,
    flags: u32,
    mtu: u32,
    session_fd: i32,
    reserved: [u32; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct SstpDetachRaw {
    reserved: [u32; 4],
}

/// Counters returned by `SSTP_IOC_GETSTATS`. Matches `struct sstp_stats`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SstpStats {
    pub tls_records_rx: u64,
    pub tls_records_tx: u64,
    pub tls_decrypt_errors: u64,
    pub sstp_frames_rx: u64,
    pub sstp_frames_tx: u64,
    pub sstp_malformed: u64,
    pub ppp_frames_rx: u64,
    pub ppp_frames_tx: u64,
    pub reserved: [u64; 8],
}

/// Event types posted to the session fd. See `kernel-abi/sstp.h`
/// `SSTP_EVT_*`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    PeerClosed = 1,
    TlsFatalAlert = 2,
    TlsRekeyNeeded = 3,
    ProtocolError = 4,
}

impl EventType {
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::PeerClosed),
            2 => Some(Self::TlsFatalAlert),
            3 => Some(Self::TlsRekeyNeeded),
            4 => Some(Self::ProtocolError),
            _ => None,
        }
    }
}

/// Wire-compatible mirror of `struct sstp_event`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventRaw {
    pub r#type: u32,
    pub arg: u32,
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// High-level surface.
// ---------------------------------------------------------------------------

/// Errors from the `/dev/sstp` wrapper.
#[derive(Debug, thiserror::Error)]
pub enum KmodError {
    /// `/dev/sstp` is not present. Either the kernel module isn't
    /// loaded, or the kernel was built without it. Caller should fall
    /// back to the userspace data path.
    #[error("/dev/sstp not present (kmod not loaded?)")]
    NotAvailable,
    /// `/dev/sstp` exists but the calling process can't open it.
    /// Usually missing `CAP_NET_ADMIN`.
    #[error("opening /dev/sstp: {0}")]
    OpenDenied(#[source] io::Error),
    /// `SSTP_IOC_ATTACH` failed. `EOPNOTSUPP` here means the TCP fd
    /// is not kTLS-equipped; `EINVAL` typically means ABI mismatch
    /// or a malformed argument.
    #[error("SSTP_IOC_ATTACH: {0}")]
    Attach(#[source] io::Error),
    /// A post-attach ioctl on the session fd failed.
    #[error("ioctl {what}: {source}")]
    Ioctl {
        what: &'static str,
        #[source]
        source: io::Error,
    },
}

/// Cheap probe: try to open `/dev/sstp` and immediately close it.
///
/// `Ok(())` means the module is loaded and the calling process can use
/// it. `Err(KmodError::NotAvailable)` means the device node is missing
/// (kmod not loaded). `Err(KmodError::OpenDenied)` means the node is
/// there but the calling process can't open it (likely missing
/// `CAP_NET_ADMIN`).
pub fn probe() -> Result<(), KmodError> {
    match open_dev_sstp() {
        Ok(_fd) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Err(KmodError::NotAvailable),
        Err(e) => Err(KmodError::OpenDenied(e)),
    }
}

/// Owned handle to a kernel-side SSTP session.
///
/// The session fd is the lifetime anchor: dropping it triggers the
/// kernel-side detach (channel unregister, callback unhook, refcount
/// release of the TCP fd). Cloning is intentionally not implemented —
/// session ownership belongs to exactly one userspace task.
#[derive(Debug)]
pub struct KmodSession {
    session_fd: OwnedFd,
    chan_index: i32,
    ppp_unit: i32,
}

impl KmodSession {
    /// Attach a TLS-protected TCP socket and a PPP unit to the kernel
    /// data path. `tcp_fd` MUST be a stream socket with kTLS RX+TX
    /// crypto already installed; otherwise the kernel returns
    /// `-EOPNOTSUPP`. `ppp_unit` is the PPP unit number (returned by
    /// `PPPIOCGUNIT` on the userspace unit fd).
    pub fn attach(
        tcp_fd: BorrowedFd<'_>,
        ppp_unit: i32,
        flags: u32,
        mtu: u32,
    ) -> Result<Self, KmodError> {
        let dev = open_dev_sstp().map_err(|e| match e.raw_os_error() {
            Some(libc::ENOENT) => KmodError::NotAvailable,
            _ => KmodError::OpenDenied(e),
        })?;

        let mut req = SstpAttachRaw {
            abi_major: SSTP_ABI_VERSION_MAJOR,
            abi_minor: SSTP_ABI_VERSION_MINOR,
            tcp_fd: tcp_fd.as_raw_fd(),
            ppp_unit,
            flags,
            mtu,
            session_fd: -1,
            reserved: [0; 4],
        };

        // SAFETY: `dev` is a freshly-opened `/dev/sstp` fd. `req`
        // matches the kernel's `struct sstp_attach` byte-for-byte
        // (verified by mirroring `kernel-abi/sstp.h`). `SSTP_IOC_ATTACH`
        // is `_IOWR(...)` of `sizeof(SstpAttachRaw)` (32 bytes), so the
        // kernel both reads and writes that many bytes through our
        // pointer. `req` is properly aligned and fully initialized.
        let rc = unsafe { libc::ioctl(dev.as_raw_fd(), SSTP_IOC_ATTACH, &raw mut req) };
        if rc < 0 {
            return Err(KmodError::Attach(io::Error::last_os_error()));
        }
        if req.session_fd < 0 {
            return Err(KmodError::Attach(io::Error::other(
                "kernel returned negative session_fd",
            )));
        }

        // SAFETY: kernel installed a fresh fd at `req.session_fd` we
        // own. The misc-device fd `dev` is dropped here — the kmod
        // model is that each open is independent and the session fd
        // carries its own lifetime.
        let session_fd = unsafe { OwnedFd::from_raw_fd(req.session_fd) };
        drop(dev);

        let chan_index = chan_index_for(session_fd.as_fd())?;

        Ok(Self {
            session_fd,
            chan_index,
            ppp_unit,
        })
    }

    /// PPP channel index assigned by `ppp_register_channel()` at
    /// attach time. Userspace passes this to `PPPIOCATTCHAN` on its
    /// `/dev/ppp` handle, then `PPPIOCCONNECT` on the unit fd, to
    /// bind the kernel-side channel to the PPP unit.
    #[must_use]
    pub fn chan_index(&self) -> i32 {
        self.chan_index
    }

    /// PPP unit number this session was attached against.
    #[must_use]
    pub fn ppp_unit(&self) -> i32 {
        self.ppp_unit
    }

    /// Borrow the session fd. Poll for `POLLIN` to learn about
    /// exceptional conditions; `read()` returns one [`EventRaw`].
    /// `POLLHUP` is reported after [`Self::detach`] (or peer close).
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.session_fd.as_fd()
    }

    /// Fetch the kernel-side stats counters.
    pub fn stats(&self) -> Result<SstpStats, KmodError> {
        let mut out = SstpStats::default();
        // SAFETY: `self.session_fd` is a valid open fd for the
        // duration of this call. `SSTP_IOC_GETSTATS` is `_IOR(...)`
        // of `sizeof(SstpStats)` (128 bytes), so the kernel writes
        // exactly that many bytes through our pointer.
        let rc = unsafe {
            libc::ioctl(
                self.session_fd.as_raw_fd(),
                SSTP_IOC_GETSTATS,
                &raw mut out,
            )
        };
        if rc < 0 {
            return Err(KmodError::Ioctl {
                what: "SSTP_IOC_GETSTATS",
                source: io::Error::last_os_error(),
            });
        }
        Ok(out)
    }

    /// Request a graceful detach. The kernel flips the session into
    /// "closing"; subsequent polls see `POLLHUP`. The actual teardown
    /// of references happens when the fd is closed (i.e. when `self`
    /// is dropped).
    pub fn detach(&self) -> Result<(), KmodError> {
        let arg = SstpDetachRaw::default();
        // SAFETY: `self.session_fd` is valid. `SSTP_IOC_DETACH` is
        // `_IOW(...)` of `sizeof(SstpDetachRaw)` (16 bytes), so the
        // kernel reads exactly that many bytes from our pointer. The
        // struct is fully initialized to zero.
        let rc = unsafe { libc::ioctl(self.session_fd.as_raw_fd(), SSTP_IOC_DETACH, &raw const arg) };
        if rc < 0 {
            return Err(KmodError::Ioctl {
                what: "SSTP_IOC_DETACH",
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    /// Read one event from the session fd. Returns `None` on
    /// `EAGAIN` (set `O_NONBLOCK` first to avoid blocking). The fd is
    /// opened blocking by default; polling externally is the usual
    /// pattern.
    pub fn read_event(&self) -> Result<Option<EventRaw>, KmodError> {
        let mut buf = [0u8; std::mem::size_of::<EventRaw>()];
        // SAFETY: `self.session_fd` is valid; `buf` is sized exactly
        // for one `EventRaw`. `read(2)` writes at most `buf.len()`
        // bytes.
        let rc = unsafe {
            libc::read(
                self.session_fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                return Ok(None);
            }
            return Err(KmodError::Ioctl {
                what: "read(session_fd)",
                source: err,
            });
        }
        #[allow(clippy::cast_sign_loss)]
        if rc as usize != buf.len() {
            return Err(KmodError::Ioctl {
                what: "read(session_fd)",
                source: io::Error::other(format!(
                    "short event read: {rc} of {}",
                    buf.len()
                )),
            });
        }
        // SAFETY: `EventRaw` is `#[repr(C)]` with three plain integer
        // fields and the buffer contains exactly `sizeof(EventRaw)`
        // bytes written by the kernel.
        let ev = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<EventRaw>()) };
        Ok(Some(ev))
    }
}

fn chan_index_for(session_fd: BorrowedFd<'_>) -> Result<i32, KmodError> {
    let mut out: libc::c_int = -1;
    // SAFETY: `session_fd` is valid. `SSTP_IOC_GET_CHAN_INDEX` is
    // `_IOR(..., int)`, so the kernel writes exactly `sizeof(int)`
    // bytes through our pointer.
    let rc =
        unsafe { libc::ioctl(session_fd.as_raw_fd(), SSTP_IOC_GET_CHAN_INDEX, &raw mut out) };
    if rc < 0 {
        return Err(KmodError::Ioctl {
            what: "SSTP_IOC_GET_CHAN_INDEX",
            source: io::Error::last_os_error(),
        });
    }
    Ok(out)
}

fn open_dev_sstp() -> io::Result<OwnedFd> {
    // SAFETY: `DEV_SSTP` is a static NUL-terminated `CStr`. `open(2)`
    // returns a fresh fd on success or -1 on error; we immediately
    // wrap it in `OwnedFd` so its lifetime is managed.
    let raw = unsafe { libc::open(DEV_SSTP.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly-opened fd we own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    /// The kernel only validates kTLS *after* the ABI check, so a
    /// plain TCP socket attach attempt is enough to confirm the
    /// wrapper's ioctl marshalling is right: we should see `EOPNOTSUPP`
    /// (the kernel's "no kTLS" rejection). Requires the kmod loaded.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN and the sstp kernel module"]
    fn attach_plain_tcp_returns_eopnotsupp() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let _accept_thread = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let sock = std::net::TcpStream::connect(addr).expect("connect");
        let err = KmodSession::attach(sock.as_fd(), 0, 0, 1500).unwrap_err();
        match err {
            KmodError::Attach(e) => {
                assert_eq!(
                    e.raw_os_error(),
                    Some(libc::EOPNOTSUPP),
                    "expected EOPNOTSUPP, got {e:?}"
                );
            }
            other => panic!("expected Attach(EOPNOTSUPP), got {other:?}"),
        }
    }

    /// `probe()` returns `NotAvailable` when /dev/sstp is missing.
    /// We can't simulate missing in a kmod-loaded environment, so this
    /// test just exercises the success path.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN and the sstp kernel module"]
    fn probe_succeeds_when_loaded() {
        probe().expect("/dev/sstp probe");
    }
}
