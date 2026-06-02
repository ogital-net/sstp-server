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

use tracing::{trace, warn};

use crate::cli::DataPathMode;

use super::SessionIpConfig;
use super::netlink::{NetlinkError, RtNetlink};
use super::sstp_kmod::{self, EventRaw, KmodError, KmodSession};
use super::tun::{TunError, TunSession};
use super::unit::{Unit, UnitError};

/// MTU we configure on `pppN` / `tun0` when RADIUS does not
/// supply `Framed-MTU` (RFC 2865 §5.12).
///
/// The value matches Microsoft RRAS and the Windows built-in
/// SSTP client, which both default to 1400. Interop with those
/// implementations is the binding constraint; the overhead
/// arithmetic below is offered as supporting evidence, not as
/// the rule that picked the number.
///
/// The underlying budget on a 1500-byte underlay path:
///
/// ```text
///   IPv4 (20) + TCP (20)                     = 40
///   TLS record:
///     TLS 1.3 AES-GCM (5+1+16)               = 22
///     TLS 1.2 AES-GCM (5+8+16)               = 29
///     TLS 1.2 AES-CBC-SHA (5+16+pad+20)      ≤ 56
///   SSTP data header ([MS-SSTP] §2.2.3)      =  4
///   PPP Address+Control+Protocol (uncompr.)  =  4
/// ```
///
/// Worst case (TLS 1.2 AES-CBC-SHA, the cipher Mikrotik /
/// `RouterOS` clients negotiate) leaves 1500 − 40 − 56 − 4 − 4 =
/// 1396 bytes of inner room. 1400 is 4 bytes over that ceiling
/// in the AES-CBC-SHA case, which the underlay TCP resegments
/// into a second outer segment for that cipher only — every
/// other cipher has slack to spare. We accept the marginal
/// resegmentation in exchange for matching the Windows /
/// RouterOS default exactly.
///
/// Operators on jumbo-frame underlays or with a known cipher /
/// version can override per-session via RADIUS `Framed-MTU`.
const DEFAULT_MTU: u32 = 1400;

fn effective_mtu(requested: Option<u32>) -> u32 {
    // Ceiling is the Ethernet payload max, not `DEFAULT_MTU`:
    // operators on jumbo or non-1500 underlays may legitimately
    // push `Framed-MTU = 1500` even though the default is lower.
    let chosen = requested.map_or(DEFAULT_MTU, |m| m.clamp(576, 1500));
    match requested {
        None => trace!(
            target: "sstp::mtu",
            default = DEFAULT_MTU,
            chosen,
            "effective_mtu: no Framed-MTU; using daemon default"
        ),
        Some(req) if req == chosen => trace!(
            target: "sstp::mtu",
            requested = req,
            chosen,
            "effective_mtu: Framed-MTU honoured as-is"
        ),
        Some(req) => trace!(
            target: "sstp::mtu",
            requested = req,
            chosen,
            min = 576,
            max = 1500,
            "effective_mtu: Framed-MTU clamped to [576, 1500]"
        ),
    }
    chosen
}

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

// INVARIANT: field declaration order encodes drop order.
//
// Rust drops struct fields in declaration order, so `unit` runs
// first (closing the `/dev/ppp` unit fd → kernel removes `pppN`),
// then `kmod` (closing the session fd → kmod detaches the channel
// and `fput`s its TCP fd reference). The two are independent on
// the kernel side — `ppp_generic` cleanly tears down a unit whose
// channel is still attached, and the kmod cleanly detaches a
// channel whose unit is gone — but we pin "remove unit, then
// detach channel" as the canonical order so a future field
// reorder can't silently flip it. `ifindex` and `mtu` are `Copy`
// scalars whose drop position is irrelevant.
//
// If you add another resource that participates in teardown
// (e.g. an explicit netlink handle), put it *after* `kmod` so the
// kernel objects it touches are already gone.
#[derive(Debug)]
struct PppBackend {
    /// Lifecycle handle for `pppN`. Drop removes the netdev.
    /// **Must drop before [`Self::kmod`]** — see invariant above.
    unit: Unit,
    /// Kernel-assigned netdev index for `pppN`. Distinct from
    /// [`Unit::index`] (the PPP unit number) — netlink wants the
    /// `IFLA_INDEX`, not the unit number.
    ifindex: u32,
    /// Negotiated MTU installed via netlink. Mirrors the value
    /// stored on the TUN backend; surfaced through
    /// [`KpppSession::mtu`] for the session-level NP filter.
    mtu: u32,
    /// Per-session sstp-kmod attach. Drop detaches the channel
    /// and releases the held TCP fd reference. **Must drop after
    /// [`Self::unit`]** — see invariant above.
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
        mtu: Option<u32>,
    ) -> Result<Self, BringUpError> {
        trace!(
            target: "sstp::mtu",
            ?mode,
            requested_mtu = ?mtu,
            %local,
            %peer,
            "KpppSession::bring_up: resolving MTU"
        );
        let mtu = effective_mtu(mtu);
        match mode {
            DataPathMode::Tun => {
                trace!(
                    target: "sstp::mtu",
                    backend = "tun",
                    mtu,
                    "bring_up: forced TUN backend"
                );
                let tun = TunSession::bring_up(local, peer, mtu)?;
                Ok(Self {
                    inner: Backend::Tun(tun),
                })
            }
            DataPathMode::Kernel => {
                trace!(
                    target: "sstp::mtu",
                    backend = "kmod",
                    mtu,
                    "bring_up: forced kernel backend"
                );
                Self::bring_up_ppp(tcp_fd, local, peer, mtu)
            }
            DataPathMode::Auto => match Self::bring_up_ppp(tcp_fd, local, peer, mtu) {
                Ok(s) => {
                    trace!(
                        target: "sstp::mtu",
                        backend = "kmod",
                        mtu,
                        "bring_up: auto resolved to kernel backend"
                    );
                    Ok(s)
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "kernel data path unavailable; falling back to TUN"
                    );
                    trace!(
                        target: "sstp::mtu",
                        backend = "tun",
                        mtu,
                        "bring_up: auto fell back to TUN backend"
                    );
                    let tun = TunSession::bring_up(local, peer, mtu)?;
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
        mtu: u32,
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
        let ifname = unit.ifname().to_string();
        let ifindex = resolve_ifindex(&ifname)?;
        let mut nl = RtNetlink::open()?;
        let cfg = SessionIpConfig {
            local,
            peer,
            netmask: None,
            mtu: Some(mtu),
        };
        nl.bring_up(ifindex, &cfg)?;

        sstp_kmod::probe()?;
        // PPP unit numbers are small non-negative; cast is lossless.
        #[allow(clippy::cast_possible_wrap)]
        let ppp_unit = unit.index() as i32;
        trace!(
            target: "sstp::mtu",
            ifname = %ifname,
            ifindex,
            ppp_unit,
            mtu,
            "bring_up_ppp: attaching kmod with negotiated MTU"
        );
        let kmod = KmodSession::attach(tcp_fd, ppp_unit, mtu)?;

        Ok(Self {
            inner: Backend::Ppp(PppBackend {
                unit,
                ifindex,
                mtu,
                kmod,
            }),
        })
    }

    #[must_use]
    pub fn ifname(&self) -> String {
        match &self.inner {
            Backend::Ppp(p) => p.unit.ifname().to_string(),
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

    /// Negotiated MTU for the data path (the value the netdev was
    /// brought up with via netlink). The session-level NP filter
    /// uses this to drop oversized inbound network-layer frames
    /// before they reach [`Self::write_ip_body`]; the kmod path
    /// already enforces MTU itself but exposes the value for
    /// uniformity.
    #[must_use]
    pub fn mtu(&self) -> u32 {
        match &self.inner {
            Backend::Ppp(p) => p.mtu,
            Backend::Tun(t) => t.mtu(),
        }
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

    /// Emit one SSTP control frame (`C=1`) through the kernel TX
    /// path. `body` is the SSTP control-message body (everything
    /// after the 4-byte outer header — [MS-SSTP] §2.2.1); the kmod
    /// prepends its own header.
    ///
    /// Always non-blocking. On socket-buffer backpressure surfaces
    /// `io::ErrorKind::WouldBlock`; the caller should wait for
    /// writability on a `WRITABLE`-registered `AsyncFd` over the
    /// underlying TCP socket and retry. Returns
    /// `io::ErrorKind::Unsupported` for the TUN backend (the
    /// session driver is expected to gate on [`Self::is_kernel`]
    /// before reaching this).
    pub fn send_control(&self, body: &[u8]) -> io::Result<()> {
        match &self.inner {
            Backend::Ppp(p) => p.kmod.send_control(body),
            Backend::Tun(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "send_control is only available on the kernel backend",
            )),
        }
    }

    /// Write a raw IP body (no PPP header) to the backing data
    /// path. The session driver decodes the PPP frame to dispatch
    /// on the protocol field and passes the bare IP body here.
    /// TUN-only — calling this in kernel mode is a programming
    /// error.
    pub async fn write_ip_body(&self, body: &[u8]) -> io::Result<usize> {
        match &self.inner {
            Backend::Ppp(_) => Err(io::Error::other(
                "write_ip_body called on kernel-mode KpppSession",
            )),
            Backend::Tun(t) => t.write_ip_body(body).await,
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
