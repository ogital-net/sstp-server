//! Per-SSTP-session data-path bring-up.
//!
//! Once IPCP converges, the session task allocates a per-session
//! data-path backend:
//!
//! - **Kernel PPP** ([`Backend::Ppp`]) — open `/dev/ppp`, allocate a
//!   fresh unit with `PPPIOCNEWUNIT`, push the negotiated MRU and
//!   the P2P address pair via netlink, then attach the kTLS-equipped
//!   TCP fd to the in-tree sstp kmod via `SSTP_IOC_ATTACH`. The
//!   kmod owns the steady-state byte path (kTLS decrypt → SSTP
//!   demux → `ppp_input`); userspace only sees control packets via
//!   the kmod event channel.
//! - **TUN** ([`Backend::Tun`]) — `/dev/net/tun`, used when the kmod
//!   is not loaded or kTLS is not negotiable. Per-packet userspace
//!   round-trip; bypass `ppp_generic` entirely.
//!
//! The legacy `/dev/ppp` userspace-copier path was removed: the
//! mainline kernel does not deliver TX frames through a unit fd
//! when no channel is attached, so without the sstp kmod the
//! unit-fd path is a no-op. TUN is the supported kmod-free option.
//!
//! Dropping a [`KpppSession`] tears down the backend (closes
//! `/dev/ppp` to remove `pppN`, or closes the tun fd).

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{BorrowedFd, OwnedFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use tracing::warn;

use crate::cli::DataPathMode;

use super::SessionIpConfig;
use super::netlink::{NetlinkError, RtNetlink};
use super::sstp_kmod::{self, EventRaw, KmodError, KmodSession};
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
    #[error("kmod: {0}")]
    Kmod(#[from] KmodError),
    #[error("tun: {0}")]
    Tun(#[from] TunError),
    #[error("resolving ifindex for {ifname}: {source}")]
    ResolveIfindex {
        ifname: String,
        #[source]
        source: io::Error,
    },
}

/// Live data-path session bound to a single SSTP session.
///
/// Dispatches between the kernel PPP path (sstp kmod) and the TUN
/// fallback. Selection happens in [`KpppSession::bring_up`].
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
    /// Per-session sstp-kmod attach. Drop detaches.
    kmod: KmodSession,
}

impl KpppSession {
    /// Resolve the operator-selected `mode` to a concrete backend
    /// and bring it up.
    ///
    /// `tcp_fd` is required for the kernel kmod attach and must
    /// have kTLS already installed; it is ignored for the TUN path.
    /// Under [`DataPathMode::Auto`] the kmod is tried first; on
    /// failure the session falls back to TUN with a warning log.
    pub fn bring_up(
        mode: DataPathMode,
        tcp_fd: BorrowedFd<'_>,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Result<Self, BringUpError> {
        match mode {
            DataPathMode::Tun => {
                let tun = TunSession::bring_up(local, peer)?;
                Ok(Self {
                    inner: Backend::Tun(tun),
                })
            }
            DataPathMode::Kernel => Self::bring_up_ppp(tcp_fd, local, peer),
            DataPathMode::Auto => match Self::bring_up_ppp(tcp_fd, local, peer) {
                Ok(s) => Ok(s),
                Err(e) => {
                    warn!(
                        error = %e,
                        "kernel data path unavailable; falling back to TUN"
                    );
                    let tun = TunSession::bring_up(local, peer)?;
                    Ok(Self {
                        inner: Backend::Tun(tun),
                    })
                }
            },
        }
    }

    fn bring_up_ppp(
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

        sstp_kmod::probe()?;
        // PPP unit numbers are small non-negative; cast is lossless.
        #[allow(clippy::cast_possible_wrap)]
        let ppp_unit = unit.index() as i32;
        let kmod = KmodSession::attach(tcp_fd, ppp_unit, DEFAULT_MTU)?;

        Ok(Self {
            inner: Backend::Ppp(PppBackend {
                unit,
                ifindex,
                kmod,
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
    /// path for this session. Always true for `Backend::Ppp`, false
    /// for TUN.
    #[must_use]
    pub fn is_kernel(&self) -> bool {
        matches!(&self.inner, Backend::Ppp(_))
    }

    /// `true` when the backend is a TUN device.
    #[must_use]
    pub fn is_tun(&self) -> bool {
        matches!(&self.inner, Backend::Tun(_))
    }

    /// Borrow the kmod session fd when running in kernel mode. The
    /// session driver wraps this in [`AsyncFd`] (READABLE) and
    /// `select!`s on it; readable means there is at least one event
    /// queued for [`Self::read_event`] to drain.
    #[must_use]
    pub fn kmod_fd(&self) -> Option<BorrowedFd<'_>> {
        match &self.inner {
            Backend::Ppp(p) => Some(p.kmod.as_fd()),
            Backend::Tun(_) => None,
        }
    }

    /// Dup the kmod session fd and wrap it in an [`AsyncFd`] for the
    /// session driver's `select!`. Returns `Ok(None)` for TUN. The
    /// dup shares the open-file-description, including the
    /// `O_NONBLOCK` flag set by [`KmodSession::attach`].
    pub fn kmod_async_fd(&self) -> io::Result<Option<AsyncFd<OwnedFd>>> {
        let Some(fd) = self.kmod_fd() else {
            return Ok(None);
        };
        let dup = fd.try_clone_to_owned()?;
        let async_fd = AsyncFd::with_interest(dup, Interest::READABLE)?;
        Ok(Some(async_fd))
    }

    /// Drain one event from the kmod session fd. Returns `None` on
    /// `EAGAIN` (queue empty) or for TUN. The fd is non-blocking;
    /// pair with an `AsyncFd::readable` wait in the caller's
    /// `select!`.
    pub fn read_event(&self) -> Result<Option<EventRaw>, KmodError> {
        match &self.inner {
            Backend::Ppp(p) => p.kmod.read_event(),
            Backend::Tun(_) => Ok(None),
        }
    }

    /// Drain one queued SSTP control packet (`C=1`, header already
    /// stripped by the kmod) into `buf`. Returns the number of
    /// payload bytes written, or `None` if the queue is empty / the
    /// backend is TUN.
    pub fn recv_control(&self, buf: &mut [u8]) -> Result<Option<usize>, KmodError> {
        match &self.inner {
            Backend::Ppp(p) => p.kmod.recv_control(buf),
            Backend::Tun(_) => Ok(None),
        }
    }

    /// Write one PPP frame to the backing data path. Only meaningful
    /// for the TUN backend; calling this in kernel mode is a
    /// programming error.
    pub async fn write_frame(&self, frame: &[u8]) -> io::Result<usize> {
        match &self.inner {
            Backend::Ppp(_) => Err(io::Error::other(
                "write_frame called on kernel-mode KpppSession",
            )),
            Backend::Tun(t) => t.write_frame(frame).await,
        }
    }

    /// Read one PPP frame from the backing data path into `buf`.
    /// Only meaningful for the TUN backend; in kernel mode the
    /// future never resolves.
    pub async fn read_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.inner {
            Backend::Ppp(_) => std::future::pending().await,
            Backend::Tun(t) => t.read_frame(buf).await,
        }
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
