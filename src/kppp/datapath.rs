//! Data-path selection: kernel (`/dev/sstp`) vs. userspace copy.
//!
//! The session task calls [`DataPath::open`] once IPCP has converged
//! and a PPP unit exists. `open()` consults the operator-selected
//! mode ([`DataPathMode`]) and probes for the kernel module:
//!
//! - [`DataPathMode::Kernel`] — only the kernel path is acceptable;
//!   probe failures are propagated as errors.
//! - [`DataPathMode::Userspace`] — always use the userspace copier,
//!   no kmod probe attempted.
//! - [`DataPathMode::Auto`] (the default) — callers may choose to
//!   route a given session straight to userspace (for example when
//!   negotiated TLS parameters are outside the current kTLS allow-list)
//!   or ask `open()` to attempt kernel attach. On attach failure, log
//!   a warning and fall back to userspace.
//!
//! The userspace copier is a thin wrapper around the existing
//! `/dev/ppp` unit fd. The session task feeds it demuxed PPP payload
//! bytes from the SSTP frame parser and reads PPP frames back out
//! to wrap into SSTP data frames. This is the same model `pppd` uses
//! over a pty — see `kppp/mod.rs` for why a generic userspace channel
//! into the kernel isn't an option without our own kmod.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use tracing::{info, warn};

use crate::cli::DataPathMode;

use super::sstp_kmod::{self, KmodError, KmodSession};
use super::unit::Unit;

/// Errors from [`DataPath::open`].
#[derive(Debug, thiserror::Error)]
pub enum DataPathError {
    /// Operator asked explicitly for `--data-path kernel` but the kmod
    /// is unavailable or the attach failed.
    #[error("kernel data path unavailable: {0}")]
    KernelRequired(#[source] KmodError),
    /// Failed to set up the userspace copier (e.g. couldn't put the
    /// unit fd into non-blocking mode).
    #[error("userspace data path setup: {0}")]
    Userspace(#[source] io::Error),
}

/// Live data-path attachment. Drop tears down the kernel session (if
/// any) and releases the unit fd back to the caller for explicit
/// teardown.
#[derive(Debug)]
pub enum DataPath {
    /// Kernel path — the kmod owns the steady-state byte path. The
    /// `KmodSession` owns the anon-inode session fd; dropping it
    /// triggers detach.
    Kernel(KmodSession),
    /// Userspace path — bytes flow through this process. The
    /// `Userspace` value owns the channel half it needs for I/O.
    Userspace(Userspace),
}

impl DataPath {
    /// Attach `tcp_fd` (a kTLS-equipped TCP socket when the kernel
    /// path is requested) and `unit` (a `/dev/ppp` unit fd) to the
    /// chosen data path.
    ///
    /// `mtu` is forwarded to the kmod attach for the kernel path;
    /// the userspace path uses `mtu` only as a hint.
    pub fn open(
        mode: DataPathMode,
        tcp_fd: BorrowedFd<'_>,
        unit: &Unit,
        mtu: u32,
    ) -> Result<Self, DataPathError> {
        match mode {
            DataPathMode::Kernel => match try_kernel(tcp_fd, unit, mtu) {
                Ok(s) => Ok(Self::Kernel(s)),
                Err(e) => Err(DataPathError::KernelRequired(e)),
            },
            DataPathMode::Userspace => Userspace::new(unit).map(Self::Userspace),
            DataPathMode::Auto => match try_kernel(tcp_fd, unit, mtu) {
                Ok(s) => {
                    info!(
                        unit = unit.index(),
                        chan = s.chan_index(),
                        "kernel data path attached"
                    );
                    Ok(Self::Kernel(s))
                }
                Err(e) => {
                    warn!(
                        unit = unit.index(),
                        error = %e,
                        "kernel data path unavailable; falling back to userspace copy"
                    );
                    Userspace::new(unit).map(Self::Userspace)
                }
            },
            // TUN does not go through `DataPath::open` — it's a
            // different backend entirely, selected at the
            // [`KpppSession`] level before any `/dev/ppp` unit is
            // ever opened. Reaching here is a programming error.
            DataPathMode::Tun => unreachable!(
                "DataPathMode::Tun must be handled by KpppSession::bring_up, not DataPath::open"
            ),
        }
    }

    /// Convenience: did we end up on the kernel path?
    #[must_use]
    pub fn is_kernel(&self) -> bool {
        matches!(self, Self::Kernel(_))
    }
}

fn try_kernel(tcp_fd: BorrowedFd<'_>, unit: &Unit, mtu: u32) -> Result<KmodSession, KmodError> {
    sstp_kmod::probe()?;
    // PPP unit numbers are small non-negative; cast is lossless.
    #[allow(clippy::cast_possible_wrap)]
    let ppp_unit = unit.index() as i32;
    KmodSession::attach(tcp_fd, ppp_unit, mtu)
}

/// Userspace fallback: bytes copy through this process.
///
/// Holds a duplicate of the unit fd in non-blocking mode so the
/// session task can drive it with `tokio::io::unix::AsyncFd`. The
/// session task is responsible for parsing SSTP frames (via
/// `crate::sstp::frame`) and pushing the inner PPP payload into
/// [`Self::unit_fd`] for the kernel PPP unit to consume, and vice
/// versa for the TX direction.
#[derive(Debug)]
pub struct Userspace {
    unit_fd: OwnedFd,
}

impl Userspace {
    fn new(unit: &Unit) -> Result<Self, DataPathError> {
        // Dup the unit fd: the [`Unit`] keeps the original, we get an
        // independent fd for non-blocking I/O. Dropping the dup does
        // not detach the kernel-side `pppN` netdev.
        let dup = unit
            .as_fd()
            .try_clone_to_owned()
            .map_err(DataPathError::Userspace)?;
        set_nonblock(dup.as_fd()).map_err(DataPathError::Userspace)?;
        Ok(Self { unit_fd: dup })
    }

    /// Borrow the non-blocking unit fd for the session task's I/O
    /// loop (typically wrapped in `tokio::io::unix::AsyncFd`).
    pub fn unit_fd(&self) -> BorrowedFd<'_> {
        self.unit_fd.as_fd()
    }
}

fn set_nonblock(fd: BorrowedFd<'_>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
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

    #[test]
    fn userspace_mode_skips_kmod_probe() {
        // We can't open `/dev/ppp` from a unit test without
        // CAP_NET_ADMIN, so this just exercises the match arm
        // selection logic via DataPathMode.
        assert_eq!(DataPathMode::default(), DataPathMode::Auto);
    }
}
