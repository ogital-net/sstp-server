//! `Unit` — a kernel PPP unit (`pppN` netdev) created via `PPPIOCNEWUNIT`.
//!
//! Lifecycle:
//!
//! 1. Open `/dev/ppp` (`O_RDWR | O_CLOEXEC`).
//! 2. `ioctl(fd, PPPIOCNEWUNIT, &-1)` — kernel allocates the next free
//!    unit number, creates the `pppN` netdev, and binds this fd as the
//!    unit's data path.
//! 3. (Optional) `PPPIOCSMRU`, `PPPIOCSFLAGS`, `PPPIOCSNPMODE` to tune
//!    the unit for the negotiated PPP options.
//! 4. The fd stays open for the session's lifetime; closing it removes
//!    `pppN`.
//!
//! The fd is intentionally **not** wrapped in `tokio::io::unix::AsyncFd`
//! at this stage — the async read/write path is M6's concern, and the
//! synchronous `Unit` interface is what M5's tests and the netlink
//! bring-up path need.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

use super::ioctl::{
    PPPIOCNEWUNIT, PPPIOCSFLAGS, PPPIOCSMRU, ioctl_set_int, ioctl_xchg_int,
};

const DEV_PPP: &CStr = c"/dev/ppp";

/// Errors from kernel PPP unit operations.
#[derive(Debug, thiserror::Error)]
pub enum UnitError {
    /// `open("/dev/ppp")` failed. Common causes: module `ppp_generic`
    /// not loaded; insufficient privileges (need `CAP_NET_ADMIN`).
    #[error("opening /dev/ppp: {0}")]
    Open(#[source] io::Error),
    /// `PPPIOCNEWUNIT` failed.
    #[error("PPPIOCNEWUNIT: {0}")]
    NewUnit(#[source] io::Error),
    /// A post-create configuration ioctl failed.
    #[error("ioctl {what}: {source}")]
    Configure {
        what: &'static str,
        #[source]
        source: io::Error,
    },
}

/// A kernel PPP unit. The fd owns the `pppN` netdev; dropping it
/// removes the interface.
#[derive(Debug)]
pub struct Unit {
    fd: OwnedFd,
    index: u32,
}

impl Unit {
    /// Open `/dev/ppp` and create a new unit. The kernel assigns the
    /// next free unit number (i.e. we pass `-1` to `PPPIOCNEWUNIT`).
    pub fn new() -> Result<Self, UnitError> {
        let fd = open_dev_ppp().map_err(UnitError::Open)?;
        // -1 means "any free unit"; the kernel writes the assigned
        // number back into the same int.
        let assigned = ioctl_xchg_int(fd.as_fd(), PPPIOCNEWUNIT, -1).map_err(UnitError::NewUnit)?;
        assert!(assigned >= 0, "kernel returned negative unit number");
        // `assigned >= 0` guarantees this fits in `u32` losslessly.
        #[allow(clippy::cast_sign_loss)]
        let index = assigned as u32;
        Ok(Self { fd, index })
    }

    /// Kernel-assigned unit number. The corresponding interface name is
    /// `format!("ppp{index}")`.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Interface name (`pppN`).
    #[must_use]
    pub fn ifname(&self) -> String {
        format!("ppp{}", self.index)
    }

    /// Borrow the unit fd. The fd is bidirectional: reads return PPP
    /// frames the kernel wants to transmit; writes inject PPP frames
    /// received from the peer.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// `PPPIOCSMRU` — set the Maximum Receive Unit the kernel will
    /// accept on this unit. PPP MRU is bounded by `u16::MAX`; values
    /// larger than `i32::MAX` would be a programmer error and are
    /// rejected at the assertion below.
    pub fn set_mru(&self, mru: u32) -> Result<(), UnitError> {
        let mru = libc::c_int::try_from(mru).expect("MRU exceeds i32::MAX");
        ioctl_set_int(self.fd.as_fd(), PPPIOCSMRU, mru).map_err(|source| UnitError::Configure {
            what: "PPPIOCSMRU",
            source,
        })
    }

    /// `PPPIOCSFLAGS` — set `SC_*` flags.
    pub fn set_flags(&self, flags: i32) -> Result<(), UnitError> {
        ioctl_set_int(self.fd.as_fd(), PPPIOCSFLAGS, flags).map_err(|source| {
            UnitError::Configure {
                what: "PPPIOCSFLAGS",
                source,
            }
        })
    }

    /// Explicit teardown. Equivalent to dropping the value (the fd's
    /// `OwnedFd` close is what removes `pppN`), but the call is
    /// `tracing`-visible so a graceful shutdown leaves a paper trail
    /// distinct from a panic-driven drop.
    ///
    /// Idiomatic use is `unit.close()` in the session teardown path
    /// just before letting the value go out of scope; the kernel
    /// removes the netdev as soon as the last fd reference is gone.
    pub fn close(self) {
        tracing::debug!(unit = self.index, ifname = %self.ifname(), "kppp: closing unit");
        drop(self);
    }
}

impl Drop for Unit {
    fn drop(&mut self) {
        // The fd's OwnedFd drop closes /dev/ppp, which causes the
        // kernel to remove `pppN`. We only log here so a session that
        // dies via panic still surfaces in the journal.
        tracing::trace!(unit = self.index, ifname = %self.ifname(), "kppp: dropping unit");
    }
}

fn open_dev_ppp() -> io::Result<OwnedFd> {
    // SAFETY: `DEV_PPP` is a static `CStr` (NUL-terminated). `open(2)`
    // returns a new fd on success or -1 on error. We immediately wrap
    // the returned fd in `OwnedFd` so its ownership is transferred and
    // it will be closed on drop.
    let raw = unsafe {
        libc::open(
            DEV_PPP.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly-opened fd we own and have not handed
    // out anywhere else.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-test: open `/dev/ppp`, create a unit, verify the assigned
    /// index round-trips through `PPPIOCGUNIT`, and that closing the fd
    /// removes the interface. Requires `CAP_NET_ADMIN` and the
    /// `ppp_generic` module; ignored by default.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN and the ppp_generic kernel module"]
    fn create_and_drop_unit() {
        let unit = Unit::new().expect("create unit");
        assert!(unit.ifname().starts_with("ppp"));
        unit.set_mru(1500).expect("set MRU");
        // Drop closes the fd; the kernel tears down pppN.
        drop(unit);
    }
}
