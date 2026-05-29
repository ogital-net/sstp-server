//! Per-SSTP-session kernel-PPP bring-up and userspace data path.
//!
//! M6g: once IPCP converges, the session task allocates a fresh
//! `/dev/ppp` unit ([`Unit`]), pushes the negotiated MRU and the
//! P2P address pair via netlink, and then drives a bidirectional
//! byte path between the TLS socket (in the session task) and the
//! kernel PPP unit fd:
//!
//! - **TX (TLS → kernel):** each PPP frame demuxed out of an SSTP
//!   `Data` packet whose Protocol is IP is written to the unit fd.
//! - **RX (kernel → TLS):** PPP frames emitted by the kernel (IPv4
//!   traffic egressing the netdev) are read from the unit fd, wrapped
//!   in an SSTP `Data` packet, and written back through TLS.
//!
//! Dropping a [`KpppSession`] closes the unit fd, which causes the
//! kernel to remove the `pppN` netdev — that's the only teardown
//! required for v0.1.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use tracing::warn;

use crate::cli::DataPathMode;

use super::SessionIpConfig;
use super::datapath::{DataPath, DataPathError};
use super::netlink::{NetlinkError, RtNetlink};
use super::sstp_kmod::{EventRaw, KmodError};
use super::tun::{TunError, TunSession};
use super::unit::{Unit, UnitError};

/// MTU we configure on `pppN`. Standard PPP default; SSTP carries
/// PPP frames inside a single SSTP data packet (max payload 4083
/// bytes per [MS-SSTP] §2.2.3), so 1500 is comfortably under the
/// transport ceiling.
const DEFAULT_MTU: u32 = 1500;

#[derive(Debug, thiserror::Error)]
pub enum BringUpError {
    #[error("opening /dev/ppp: {0}")]
    Unit(#[from] UnitError),
    #[error("netlink: {0}")]
    Netlink(#[from] NetlinkError),
    #[error("data path: {0}")]
    DataPath(#[from] DataPathError),
    #[error("tun: {0}")]
    Tun(#[from] TunError),
    #[error("duplicating unit fd for async I/O: {0}")]
    Dup(#[source] io::Error),
    #[error("registering unit fd with tokio: {0}")]
    Register(#[source] io::Error),
    #[error("resolving ifindex for {ifname}: {source}")]
    ResolveIfindex {
        ifname: String,
        #[source]
        source: io::Error,
    },
}

/// Live data-path session bound to a single SSTP session.
///
/// Dispatches between two backends:
///
/// - **PPP** — a `/dev/ppp` unit fd plus an attached [`DataPath`]
///   (kernel kmod or userspace copy). Used when the operator asks
///   for `--data-path kernel` or `--data-path userspace`, and the
///   first choice tried under `--data-path auto`.
/// - **TUN** — a plain `/dev/net/tun` netdev. Used under
///   `--data-path tun` and as the fallback under `--data-path auto`
///   when the kmod attach fails. This is the path that actually
///   moves IP traffic on mainline kernels without the sstp kmod.
#[derive(Debug)]
pub struct KpppSession {
    inner: Backend,
}

#[derive(Debug)]
enum Backend {
    Ppp(PppBackend),
    Tun(TunSession),
}

#[derive(Debug)]
struct PppBackend {
    /// Lifecycle handle for `pppN`. Drop removes the netdev.
    unit: Unit,
    /// Kernel-assigned netdev index for `pppN`. Distinct from
    /// [`Unit::index`] (the PPP unit number) — netlink wants the
    /// `IFLA_INDEX`, not the unit number.
    ifindex: u32,
    /// Per-session data-path attachment. `Kernel` means the SSTP
    /// kmod owns the steady-state byte path; `Userspace` means
    /// frames flow through this process via [`Self::async_fd`].
    path: DataPath,
    /// Userspace mode only: async-wrapped duplicate of the unit fd
    /// for the session task's `select!`. `None` in kernel mode.
    async_fd: Option<AsyncFd<OwnedFd>>,
}

impl KpppSession {
    /// Resolve the operator-selected `mode` to a concrete backend,
    /// bring it up, and return a live session.
    ///
    /// `tcp_fd` is required for the kernel kmod attach but ignored
    /// for the userspace and TUN paths. Under `DataPathMode::Auto`,
    /// the kmod is tried first; on failure the session falls back
    /// to TUN (the legacy PPP-userspace copier is a no-op on
    /// mainline kernels and is reachable only via the explicit
    /// `--data-path userspace` flag).
    pub fn bring_up(
        mode: DataPathMode,
        tcp_fd: BorrowedFd<'_>,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Result<Self, BringUpError> {
        match mode {
            DataPathMode::Tun => {
                let tun = TunSession::bring_up(local, peer)?;
                return Ok(Self {
                    inner: Backend::Tun(tun),
                });
            }
            DataPathMode::Auto => {
                // Try the PPP+kmod path first; if it fails, fall
                // back to TUN. The PPP-userspace path is *not*
                // tried under Auto because it doesn't move IP
                // traffic on mainline kernels.
                match Self::bring_up_ppp(DataPathMode::Kernel, tcp_fd, local, peer) {
                    Ok(s) => return Ok(s),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "kernel data path unavailable; falling back to TUN"
                        );
                        let tun = TunSession::bring_up(local, peer)?;
                        return Ok(Self {
                            inner: Backend::Tun(tun),
                        });
                    }
                }
            }
            DataPathMode::Kernel | DataPathMode::Userspace => {}
        }
        Self::bring_up_ppp(mode, tcp_fd, local, peer)
    }

    fn bring_up_ppp(
        mode: DataPathMode,
        tcp_fd: BorrowedFd<'_>,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Result<Self, BringUpError> {
        let unit = Unit::new()?;
        // Skip PPPIOCSMRU: in mainline kernels (≥6.x) the unit-fd
        // dispatch returns ENOTTY for it (PPPIOCSMRU is a channel
        // ioctl). The netlink `IFLA_MTU` below is what the kernel
        // honours on the data path; LCP MRU negotiation is already
        // settled by our in-process PPP FSM.
        // The PPP unit number is *not* the netdev `ifindex` — resolve
        // the kernel-assigned `IFLA_INDEX` from the netdev name so
        // RTM_NEWADDR/RTM_NEWLINK target the right interface (without
        // this, addresses land on whatever netdev happens to have
        // `ifindex == unit_number`, typically `lo`).
        let ifname = unit.ifname();
        let ifindex = resolve_ifindex(&ifname)?;
        let mut nl = RtNetlink::open()?;
        let cfg = SessionIpConfig {
            local,
            peer,
            netmask: None,
            mtu: Some(DEFAULT_MTU),
        };
        nl.bring_up(ifindex, &cfg)?;

        let path = DataPath::open(mode, tcp_fd, &unit, DEFAULT_MTU)?;

        let async_fd = match &path {
            DataPath::Kernel(_) => None,
            DataPath::Userspace(_) => {
                // `try_clone_to_owned` is `dup3(F_DUPFD_CLOEXEC)`;
                // both fds share the same open-file-description,
                // including the `O_NONBLOCK` flag that `Unit::new`
                // already set.
                let dup = unit
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(BringUpError::Dup)?;
                Some(
                    AsyncFd::with_interest(dup, Interest::READABLE | Interest::WRITABLE)
                        .map_err(BringUpError::Register)?,
                )
            }
        };

        Ok(Self {
            inner: Backend::Ppp(PppBackend {
                unit,
                ifindex,
                path,
                async_fd,
            }),
        })
    }

    #[must_use]
    pub fn ifname(&self) -> String {
        match &self.inner {
            Backend::Ppp(p) => p.unit.ifname(),
            Backend::Tun(t) => t.ifname().to_string(),
        }
    }

    #[must_use]
    pub fn ifindex(&self) -> u32 {
        match &self.inner {
            Backend::Ppp(p) => p.ifindex,
            Backend::Tun(t) => t.ifindex(),
        }
    }

    /// `true` when the kernel SSTP module owns the steady-state byte
    /// path for this session. The session driver uses this to skip
    /// its userspace copy loop. False for TUN and for the PPP
    /// userspace fallback.
    #[must_use]
    pub fn is_kernel(&self) -> bool {
        matches!(&self.inner, Backend::Ppp(p) if p.path.is_kernel())
    }

    /// `true` when the backend is a TUN device. Lets the session
    /// driver know an EOF from `read_frame` is a real error (TUN
    /// reads return packets, not EOF) rather than the
    /// channel-less-pppN no-op behaviour.
    #[must_use]
    pub fn is_tun(&self) -> bool {
        matches!(&self.inner, Backend::Tun(_))
    }

    /// Borrow the kmod session fd when running in kernel mode. The
    /// session driver wraps this in [`AsyncFd`] (READABLE) and
    /// `select!`s on it; readable means there is at least one event
    /// queued for [`Self::read_event`] to drain.
    ///
    /// Returns `None` for TUN and userspace-PPP backends.
    #[must_use]
    pub fn kmod_fd(&self) -> Option<BorrowedFd<'_>> {
        match &self.inner {
            Backend::Ppp(p) => match &p.path {
                DataPath::Kernel(s) => Some(s.as_fd()),
                DataPath::Userspace(_) => None,
            },
            Backend::Tun(_) => None,
        }
    }

    /// Dup the kmod session fd and wrap it in an [`AsyncFd`] for the
    /// session driver's `select!`. Returns `Ok(None)` for non-kernel
    /// backends. The dup shares the open-file-description, including
    /// the `O_NONBLOCK` flag set by [`KmodSession::attach`].
    pub fn kmod_async_fd(&self) -> io::Result<Option<AsyncFd<OwnedFd>>> {
        let Some(fd) = self.kmod_fd() else {
            return Ok(None);
        };
        let dup = fd.try_clone_to_owned()?;
        let async_fd = AsyncFd::with_interest(dup, Interest::READABLE)?;
        Ok(Some(async_fd))
    }

    /// Drain one event from the kmod session fd. Returns `None` on
    /// `EAGAIN` (queue empty) or when the backend is not kernel
    /// mode. The fd is non-blocking; pair with an `AsyncFd::readable`
    /// wait in the caller's `select!`.
    pub fn read_event(&self) -> Result<Option<EventRaw>, KmodError> {
        match &self.inner {
            Backend::Ppp(p) => match &p.path {
                DataPath::Kernel(s) => s.read_event(),
                DataPath::Userspace(_) => Ok(None),
            },
            Backend::Tun(_) => Ok(None),
        }
    }

    /// Drain one queued SSTP control packet (`C=1`, header already
    /// stripped by the kmod) into `buf`. Returns the number of
    /// payload bytes written, `None` if the queue is empty, or
    /// `None` for non-kernel-mode backends.
    ///
    /// Pair with a `SSTP_EVT_CONTROL_PACKET` event seen via
    /// [`Self::read_event`].
    pub fn recv_control(&self, buf: &mut [u8]) -> Result<Option<usize>, KmodError> {
        match &self.inner {
            Backend::Ppp(p) => match &p.path {
                DataPath::Kernel(s) => s.recv_control(buf),
                DataPath::Userspace(_) => Ok(None),
            },
            Backend::Tun(_) => Ok(None),
        }
    }

    /// Write one PPP frame to the backing data path.
    ///
    /// - PPP backend: the bytes go straight to the unit fd.
    /// - TUN backend: the PPP header is stripped and just the IP
    ///   payload is written to the tun fd.
    ///
    /// Calling this in kernel mode is a programming error.
    pub async fn write_frame(&self, frame: &[u8]) -> io::Result<usize> {
        match &self.inner {
            Backend::Ppp(p) => {
                let fd = p.async_fd.as_ref().ok_or_else(|| {
                    io::Error::other("write_frame called on kernel-mode KpppSession")
                })?;
                fd.async_io(Interest::WRITABLE, |fd| write_fd(fd.as_fd(), frame))
                    .await
            }
            Backend::Tun(t) => t.write_frame(frame).await,
        }
    }

    /// Read one PPP frame from the backing data path into `buf`.
    ///
    /// - PPP backend: bytes read from the unit fd verbatim.
    /// - TUN backend: an IP packet is read from the tun fd and
    ///   PPP-encoded (uncompressed header + protocol field) into
    ///   `buf`.
    ///
    /// In kernel mode the future will never resolve.
    pub async fn read_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.inner {
            Backend::Ppp(p) => {
                let fd = p.async_fd.as_ref().ok_or_else(|| {
                    io::Error::other("read_frame called on kernel-mode KpppSession")
                })?;
                fd.async_io(Interest::READABLE, |fd| read_fd(fd.as_fd(), buf))
                    .await
            }
            Backend::Tun(t) => t.read_frame(buf).await,
        }
    }
}

/// `write(2)` against a borrowed fd, returning `WouldBlock` on `EAGAIN`
/// so [`AsyncFd::async_io`] can re-arm and retry.
fn write_fd(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `fd` is valid for the duration of the call; `buf` is a
    // valid initialised slice.
    let rc = unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(usize::try_from(rc).expect("non-negative ssize_t"))
    }
}

/// `read(2)` against a borrowed fd, returning `WouldBlock` on `EAGAIN`
/// so [`AsyncFd::async_io`] can re-arm and retry.
fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is valid for the duration of the call; `buf` is a
    // valid initialised slice we have exclusive access to.
    let rc = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(usize::try_from(rc).expect("non-negative ssize_t"))
    }
}

/// Resolve a netdev name to its kernel `ifindex` via `if_nametoindex(3)`.
fn resolve_ifindex(ifname: &str) -> Result<u32, BringUpError> {
    let cstr = std::ffi::CString::new(ifname).expect("ifname has no NUL");
    // SAFETY: `cstr` is a valid NUL-terminated C string for the
    // duration of the call. `if_nametoindex` returns 0 on error and
    // sets errno; any non-zero return is a valid ifindex.
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        Err(BringUpError::ResolveIfindex {
            ifname: ifname.to_string(),
            source: io::Error::last_os_error(),
        })
    } else {
        Ok(idx)
    }
}
