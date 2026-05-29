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

use crate::cli::DataPathMode;

use super::SessionIpConfig;
use super::datapath::{DataPath, DataPathError};
use super::netlink::{NetlinkError, RtNetlink};
use super::sstp_kmod::SSTP_F_PFC;
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
    #[error("duplicating unit fd for async I/O: {0}")]
    Dup(#[source] io::Error),
    #[error("registering unit fd with tokio: {0}")]
    Register(#[source] io::Error),
}

/// Live kernel-PPP session bound to a single SSTP session.
///
/// Holds the `pppN` netdev ([`Unit`]) plus whichever data path the
/// session ended up on. Dropping closes the unit fd (the kernel then
/// removes the `pppN` netdev) and any kernel-side `/dev/sstp`
/// attachment.
#[derive(Debug)]
pub struct KpppSession {
    /// Lifecycle handle for `pppN`. Drop removes the netdev.
    unit: Unit,
    /// Per-session data-path attachment. `Kernel` means the SSTP
    /// kmod owns the steady-state byte path; `Userspace` means
    /// frames flow through this process via [`Self::async_fd`].
    path: DataPath,
    /// Userspace mode only: async-wrapped duplicate of the unit fd
    /// for the session task's `select!`. `None` in kernel mode.
    async_fd: Option<AsyncFd<OwnedFd>>,
}

impl KpppSession {
    /// Allocate `pppN`, configure MRU, push the P2P address pair,
    /// and attach the chosen data path.
    ///
    /// `tcp_fd` is required for the kernel path (`SSTP_IOC_ATTACH`
    /// hands the socket to the kmod) but ignored for userspace.
    /// `mode` resolves the kernel-vs-userspace decision per the
    /// CLI / startup probe (see [`DataPath::open`]).
    pub fn bring_up(
        mode: DataPathMode,
        tcp_fd: BorrowedFd<'_>,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Result<Self, BringUpError> {
        let unit = Unit::new()?;
        unit.set_mru(DEFAULT_MTU).map_err(BringUpError::Unit)?;
        let mut nl = RtNetlink::open()?;
        let cfg = SessionIpConfig {
            local,
            peer,
            netmask: None,
            mtu: Some(DEFAULT_MTU),
        };
        nl.bring_up(unit.index(), &cfg)?;

        // The kmod attach derives no value from PPP option flags
        // beyond what's already baked into the unit fd; we pass
        // `SSTP_F_PFC` as the only currently-meaningful hint. ACFC
        // is implied by uncompressed Address/Control bytes on the
        // wire, and IPV6CP isn't a v0.1 feature.
        let path = DataPath::open(mode, tcp_fd, &unit, SSTP_F_PFC, DEFAULT_MTU)?;

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
            unit,
            path,
            async_fd,
        })
    }

    #[must_use]
    pub fn ifname(&self) -> String {
        self.unit.ifname()
    }

    #[must_use]
    pub fn ifindex(&self) -> u32 {
        self.unit.index()
    }

    /// `true` when the kernel SSTP module owns the steady-state byte
    /// path for this session. The session driver uses this to skip
    /// its userspace copy loop.
    #[must_use]
    pub fn is_kernel(&self) -> bool {
        self.path.is_kernel()
    }

    /// Write one PPP frame to the kernel unit fd. Userspace mode
    /// only; calling this in kernel mode is a programming error.
    pub async fn write_frame(&self, frame: &[u8]) -> io::Result<usize> {
        let fd = self.async_fd.as_ref().ok_or_else(|| {
            io::Error::other("write_frame called on kernel-mode KpppSession")
        })?;
        fd.async_io(Interest::WRITABLE, |fd| write_fd(fd.as_fd(), frame))
            .await
    }

    /// Read one PPP frame from the kernel unit fd into `buf`.
    /// Userspace mode only; in kernel mode the future will never
    /// resolve (the session driver instead selects on a `pending()`
    /// branch for this slot).
    pub async fn read_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.async_fd.as_ref().ok_or_else(|| {
            io::Error::other("read_frame called on kernel-mode KpppSession")
        })?;
        fd.async_io(Interest::READABLE, |fd| read_fd(fd.as_fd(), buf))
            .await
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
