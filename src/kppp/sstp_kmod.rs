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

// Mirrors the full `kernel-abi/sstp.h` ABI surface. Stats / detach
// ioctl wrappers and accessor methods are present so the data-path
// driver can consume them without further FFI work; they have no
// caller in the binary today (M5 wires probe + attach only).
#![allow(dead_code)]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use super::ioctl::{
    PPPIOCATTCHAN, PPPIOCCONNECT, ioc_none, ioc_read, ioc_readwrite, ioctl_set_int,
};

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
pub const SSTP_ABI_VERSION_MINOR: u16 = 2;

const SSTP_IOC_MAGIC: u8 = b'S';

const SSTP_IOC_ATTACH: libc::c_ulong = ioc_readwrite::<SstpAttachRaw>(SSTP_IOC_MAGIC, 0x80);
const SSTP_IOC_DETACH: libc::c_ulong = ioc_none(SSTP_IOC_MAGIC, 0x81);
const SSTP_IOC_GETSTATS: libc::c_ulong = ioc_read::<SstpStats>(SSTP_IOC_MAGIC, 0x82);
const SSTP_IOC_GET_CHAN_INDEX: libc::c_ulong = ioc_read::<libc::c_int>(SSTP_IOC_MAGIC, 0x83);
const SSTP_IOC_RECV_CONTROL: libc::c_ulong =
    ioc_readwrite::<SstpRecvControlRaw>(SSTP_IOC_MAGIC, 0x84);

/// Maximum SSTP control-packet payload userspace may need to drain.
/// Matches `SSTP_CONTROL_MAX` in `kernel-abi/sstp.h`. The kernel
/// drops queued frames whose payload exceeds the caller's `buf_len`
/// with `EMSGSIZE` (no requeue — head-side requeue would break
/// ordering), so the caller's buffer must be sized at least this
/// large.
pub const SSTP_CONTROL_MAX: usize = 4096;

/// Wire-compatible mirror of `struct sstp_attach`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SstpAttachRaw {
    abi_major: u16,
    abi_minor: u16,
    tcp_fd: i32,
    mtu: u32,
    session_fd: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SstpRecvControlRaw {
    buf_len: u32,
    payload_len: u32,
    buf: u64,
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
    pub evt_dropped: u64,
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
    /// A control packet (C=1) was demuxed by the kmod and queued for
    /// userspace. The event's `arg` is the payload length; drain it
    /// with [`KmodSession::recv_control`].
    ControlPacket = 5,
}

impl EventType {
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::PeerClosed),
            2 => Some(Self::TlsFatalAlert),
            3 => Some(Self::TlsRekeyNeeded),
            4 => Some(Self::ProtocolError),
            5 => Some(Self::ControlPacket),
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
    /// Binding the kernel SSTP channel to the userspace PPP unit
    /// failed. Returned wrapped errno from `PPPIOCATTCHAN` or
    /// `PPPIOCCONNECT` on a fresh `/dev/ppp` handle.
    #[error("binding channel to PPP unit ({what}): {source}")]
    ChannelBind {
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
    /// `/dev/ppp` fd that anchors the channel↔unit binding. Closing
    /// it disconnects the channel from the unit; we hold it for the
    /// session's lifetime so the kernel keeps the PPP data path
    /// wired together.
    chan_fd: OwnedFd,
    chan_index: i32,
    ppp_unit: i32,
}

impl KmodSession {
    /// Attach a TLS-protected TCP socket and a PPP unit to the kernel
    /// data path. `tcp_fd` MUST be a stream socket with kTLS RX+TX
    /// crypto already installed; otherwise the kernel returns
    /// `-EOPNOTSUPP`. `ppp_unit` is the PPP unit number (returned by
    /// `PPPIOCGUNIT` on the userspace unit fd) — it is not part of
    /// the kmod ABI; it is used here to bind the registered SSTP
    /// channel to the unit via the standard `ppp_generic` ioctls.
    pub fn attach(tcp_fd: BorrowedFd<'_>, ppp_unit: i32, mtu: u32) -> Result<Self, KmodError> {
        let dev = open_dev_sstp().map_err(|e| match e.raw_os_error() {
            Some(libc::ENOENT) => KmodError::NotAvailable,
            _ => KmodError::OpenDenied(e),
        })?;

        let mut req = SstpAttachRaw {
            abi_major: SSTP_ABI_VERSION_MAJOR,
            abi_minor: SSTP_ABI_VERSION_MINOR,
            tcp_fd: tcp_fd.as_raw_fd(),
            mtu,
            session_fd: -1,
        };

        // SAFETY: `dev` is a freshly-opened `/dev/sstp` fd. `req`
        // matches the kernel's `struct sstp_attach` byte-for-byte
        // (verified by mirroring `kernel-abi/sstp.h`). `SSTP_IOC_ATTACH`
        // is `_IOWR(...)` of `sizeof(SstpAttachRaw)` (16 bytes), so the
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

        // The kmod opens the session fd in blocking mode; mark it
        // O_NONBLOCK so async drivers can `read(2)` events without
        // stalling the I/O worker. `read_event` translates EAGAIN
        // into `Ok(None)`.
        set_nonblock(session_fd.as_fd()).map_err(|source| KmodError::Ioctl {
            what: "fcntl(O_NONBLOCK) on session_fd",
            source,
        })?;

        let chan_index = chan_index_for(session_fd.as_fd())?;

        // Bind the kernel SSTP channel to the userspace PPP unit.
        // The kmod registers a channel in attach but does not bind
        // it to a unit — that is userspace's responsibility per the
        // ppp_generic ABI. Open a fresh `/dev/ppp` fd, attach it to
        // the kmod's channel with PPPIOCATTCHAN, then connect that
        // channel to the unit with PPPIOCCONNECT. The fd must stay
        // open for the session's lifetime; closing it disconnects.
        let chan_fd = bind_channel_to_unit(chan_index, ppp_unit)?;

        Ok(Self {
            session_fd,
            chan_fd,
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
        // of `sizeof(SstpStats)` (72 bytes), so the kernel writes
        // exactly that many bytes through our pointer.
        let rc =
            unsafe { libc::ioctl(self.session_fd.as_raw_fd(), SSTP_IOC_GETSTATS, &raw mut out) };
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
        // SAFETY: `self.session_fd` is valid. `SSTP_IOC_DETACH` is
        // `_IO(...)` (no payload); the third argument is ignored by
        // the kernel.
        let rc = unsafe { libc::ioctl(self.session_fd.as_raw_fd(), SSTP_IOC_DETACH, 0) };
        if rc < 0 {
            return Err(KmodError::Ioctl {
                what: "SSTP_IOC_DETACH",
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    /// Read one event from the session fd. Returns `None` on
    /// `EAGAIN`. The fd is set non-blocking at attach time, so this
    /// is safe to call from an async context wrapped in
    /// `tokio::io::unix::AsyncFd::readable().await`.
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
                source: io::Error::other(format!("short event read: {rc} of {}", buf.len())),
            });
        }
        // SAFETY: `EventRaw` is `#[repr(C)]` with three plain integer
        // fields and the buffer contains exactly `sizeof(EventRaw)`
        // bytes written by the kernel.
        let ev = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<EventRaw>()) };
        Ok(Some(ev))
    }

    /// Drain one queued SSTP control packet (C=1, header already
    /// stripped by the kmod) into `buf`. Returns the number of
    /// payload bytes written, or `None` if the queue is empty.
    ///
    /// `buf` must be at least [`SSTP_CONTROL_MAX`] bytes; smaller
    /// buffers risk `EMSGSIZE` for a frame the kmod will then
    /// requeue for retry. Pair with a wait on `SSTP_EVT_CONTROL_PACKET`
    /// surfaced through [`Self::read_event`].
    pub fn recv_control(&self, buf: &mut [u8]) -> Result<Option<usize>, KmodError> {
        let mut req = SstpRecvControlRaw {
            buf_len: u32::try_from(buf.len()).unwrap_or(u32::MAX),
            payload_len: 0,
            buf: buf.as_mut_ptr() as u64,
        };
        // SAFETY: `self.session_fd` is a valid open fd. `SSTP_IOC_RECV_CONTROL`
        // is `_IOWR(...)` of `sizeof(SstpRecvControlRaw)` (16 bytes);
        // the kernel both reads and writes that many bytes through
        // our pointer. `req.buf` points at `buf`, which lives for the
        // duration of this call (the kernel only dereferences it
        // synchronously inside the ioctl).
        let rc = unsafe {
            libc::ioctl(
                self.session_fd.as_raw_fd(),
                SSTP_IOC_RECV_CONTROL,
                &raw mut req,
            )
        };
        if rc < 0 {
            return Err(KmodError::Ioctl {
                what: "SSTP_IOC_RECV_CONTROL",
                source: io::Error::last_os_error(),
            });
        }
        if rc == 0 {
            return Ok(None);
        }
        // The ioctl returns the payload length on success; the same
        // value lands in `req.payload_len`. Trust either, but assert
        // they agree to catch ABI drift early.
        debug_assert_eq!(u32::try_from(rc).unwrap_or(u32::MAX), req.payload_len);
        #[allow(clippy::cast_sign_loss)]
        Ok(Some(rc as usize))
    }
}

fn chan_index_for(session_fd: BorrowedFd<'_>) -> Result<i32, KmodError> {
    let mut out: libc::c_int = -1;
    // SAFETY: `session_fd` is valid. `SSTP_IOC_GET_CHAN_INDEX` is
    // `_IOR(..., int)`, so the kernel writes exactly `sizeof(int)`
    // bytes through our pointer.
    let rc = unsafe {
        libc::ioctl(
            session_fd.as_raw_fd(),
            SSTP_IOC_GET_CHAN_INDEX,
            &raw mut out,
        )
    };
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

/// Open `/dev/ppp`, attach to the kmod's PPP channel by index, and
/// connect that channel to the given PPP unit. Returns the channel
/// fd, which must outlive the session — closing it disconnects the
/// channel.
fn bind_channel_to_unit(chan_index: i32, ppp_unit: i32) -> Result<OwnedFd, KmodError> {
    // SAFETY: static NUL-terminated `CStr`; `open(2)` returns a fresh
    // fd or -1.
    let raw = unsafe { libc::open(c"/dev/ppp".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(KmodError::ChannelBind {
            what: "open(/dev/ppp)",
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `raw` is a freshly opened fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    ioctl_set_int(fd.as_fd(), PPPIOCATTCHAN, chan_index).map_err(|source| {
        KmodError::ChannelBind {
            what: "PPPIOCATTCHAN",
            source,
        }
    })?;
    ioctl_set_int(fd.as_fd(), PPPIOCCONNECT, ppp_unit).map_err(|source| {
        KmodError::ChannelBind {
            what: "PPPIOCCONNECT",
            source,
        }
    })?;
    Ok(fd)
}

fn set_nonblock(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: `fd` is a valid open fd for the duration of the call.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
        let err = KmodSession::attach(sock.as_fd(), 0, 1500).unwrap_err();
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

    /// Pin the SSTP ioctl numbers against the values the kernel
    /// computes for `_IOR/_IOW/_IOWR` over the matching structs.
    /// Independent of architecture (the kmod is `__u`-typed
    /// throughout, so `sizeof` is fixed). Numbers must stay in lock
    /// step with `kernel-abi/sstp.h`.
    #[test]
    fn sstp_ioctl_numbers_match_kernel() {
        // _IOWR('S', 0x80, struct sstp_attach) — 16 bytes
        assert_eq!(SSTP_IOC_ATTACH, 0xc010_5380);
        // _IO('S', 0x81) — no payload
        assert_eq!(SSTP_IOC_DETACH, 0x0000_5381);
        // _IOR('S', 0x82, struct sstp_stats) — 72 bytes (9 × u64)
        assert_eq!(SSTP_IOC_GETSTATS, 0x8048_5382);
        // _IOR('S', 0x83, __s32) — 4 bytes
        assert_eq!(SSTP_IOC_GET_CHAN_INDEX, 0x8004_5383);
        // _IOWR('S', 0x84, struct sstp_recv_control) — 16 bytes
        assert_eq!(SSTP_IOC_RECV_CONTROL, 0xc010_5384);
    }

    #[test]
    fn recv_control_struct_is_16_bytes() {
        assert_eq!(core::mem::size_of::<SstpRecvControlRaw>(), 16);
    }

    #[test]
    fn control_packet_event_round_trips() {
        assert_eq!(EventType::from_u32(5), Some(EventType::ControlPacket));
        assert_eq!(EventType::ControlPacket as u32, 5);
    }
}
