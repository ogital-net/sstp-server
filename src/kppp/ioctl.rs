//! `/dev/ppp` ioctl numbers and minimal `unsafe` wrappers.
//!
//! Numbers mirror `<linux/ppp-ioctl.h>` from the mainline kernel; we
//! compute them with [`const fn`] equivalents of the kernel's
//! `_IO`/`_IOR`/`_IOW`/`_IOWR` macros so the values are
//! self-documenting and amenable to a compile-time check against the
//! canonical resolved values (see the test at the bottom).

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
// ---------------------------------------------------------------------------
// `_IOC` macro family, ported from <asm-generic/ioctl.h>.
// ---------------------------------------------------------------------------

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

#[inline]
const fn ioc(dir: u32, typ: u8, nr: u8, size: usize) -> libc::c_ulong {
    // `size` always comes from `core::mem::size_of::<T>()` for the small
    // POD types these ioctls take (`int`, `struct npioctl`), so the
    // truncation to `u32` cannot lose information in practice. The
    // `_IOC_SIZEBITS` field is only 14 bits wide anyway, so anything
    // larger would be rejected by the kernel.
    #[allow(clippy::cast_possible_truncation)]
    let size = size as u32;
    let v = (dir << IOC_DIRSHIFT)
        | ((typ as u32) << IOC_TYPESHIFT)
        | ((nr as u32) << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT);
    v as libc::c_ulong
}

#[inline]
const fn io(typ: u8, nr: u8) -> libc::c_ulong {
    ioc(IOC_NONE, typ, nr, 0)
}

#[inline]
const fn ior<T>(typ: u8, nr: u8) -> libc::c_ulong {
    ioc(IOC_READ, typ, nr, core::mem::size_of::<T>())
}

#[inline]
const fn iow<T>(typ: u8, nr: u8) -> libc::c_ulong {
    ioc(IOC_WRITE, typ, nr, core::mem::size_of::<T>())
}

#[inline]
const fn iowr<T>(typ: u8, nr: u8) -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, typ, nr, core::mem::size_of::<T>())
}

/// Crate-internal alias of the `_IOR(type, nr, T)` macro for use by
/// sibling modules (e.g. `sstp_kmod`) that compose their own ioctl
/// number sets.
#[inline]
pub(crate) const fn ioc_read<T>(typ: u8, nr: u8) -> libc::c_ulong {
    ior::<T>(typ, nr)
}

/// Crate-internal alias of `_IOW(type, nr, T)`.
#[inline]
pub(crate) const fn ioc_write<T>(typ: u8, nr: u8) -> libc::c_ulong {
    iow::<T>(typ, nr)
}

/// Crate-internal alias of `_IOWR(type, nr, T)`.
#[inline]
pub(crate) const fn ioc_readwrite<T>(typ: u8, nr: u8) -> libc::c_ulong {
    iowr::<T>(typ, nr)
}

// ---------------------------------------------------------------------------
// PPP ioctls — `<linux/ppp-ioctl.h>` type byte is `'t'` (0x74).
// ---------------------------------------------------------------------------

const PPP_T: u8 = b't';

/// `PPPIOCGCHAN` — get the channel index for a fd attached to a channel.
pub const PPPIOCGCHAN: libc::c_ulong = ior::<libc::c_int>(PPP_T, 55);
/// `PPPIOCATTCHAN` — attach a `/dev/ppp` fd to an existing channel by index.
pub const PPPIOCATTCHAN: libc::c_ulong = iow::<libc::c_int>(PPP_T, 56);
/// `PPPIOCDISCONN` — disconnect a channel fd from its unit.
pub const PPPIOCDISCONN: libc::c_ulong = io(PPP_T, 57);
/// `PPPIOCCONNECT` — connect a channel fd to a unit by unit number.
pub const PPPIOCCONNECT: libc::c_ulong = iow::<libc::c_int>(PPP_T, 58);
/// `PPPIOCSMRRU` — set multilink reconstructed-receive-unit.
pub const PPPIOCSMRRU: libc::c_ulong = iow::<libc::c_int>(PPP_T, 59);
/// `PPPIOCDETACH` — detach a fd from a unit.
pub const PPPIOCDETACH: libc::c_ulong = iow::<libc::c_int>(PPP_T, 60);
/// `PPPIOCATTACH` — attach a `/dev/ppp` fd to an existing unit by index.
pub const PPPIOCATTACH: libc::c_ulong = iow::<libc::c_int>(PPP_T, 61);
/// `PPPIOCNEWUNIT` — create a new PPP unit; input is requested unit
/// number (or `-1` for kernel-assigned), output is the assigned number.
pub const PPPIOCNEWUNIT: libc::c_ulong = iowr::<libc::c_int>(PPP_T, 62);
/// `PPPIOCSNPMODE` — set Network-Protocol mode (pass/silent/drop/...).
pub const PPPIOCSNPMODE: libc::c_ulong = iow::<NpIoctl>(PPP_T, 75);
/// `PPPIOCSMRU` — set Maximum Receive Unit on the unit.
pub const PPPIOCSMRU: libc::c_ulong = iow::<libc::c_int>(PPP_T, 83);
/// `PPPIOCGUNIT` — get the unit number for a unit fd.
pub const PPPIOCGUNIT: libc::c_ulong = ior::<libc::c_int>(PPP_T, 86);
/// `PPPIOCSFLAGS` — set unit flags (`SC_*`).
pub const PPPIOCSFLAGS: libc::c_ulong = iow::<libc::c_int>(PPP_T, 89);
/// `PPPIOCGFLAGS` — get unit flags.
pub const PPPIOCGFLAGS: libc::c_ulong = ior::<libc::c_int>(PPP_T, 90);

/// `struct npioctl` payload for [`PPPIOCSNPMODE`].
///
/// Layout matches `<linux/ppp-ioctl.h>`:
/// ```c
/// struct npioctl {
///     int  protocol;  /* PPP protocol number, host byte order */
///     enum NPmode mode;
/// };
/// ```
/// `enum NPmode` is an `int` on Linux ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NpIoctl {
    pub protocol: libc::c_int,
    pub mode: libc::c_int,
}

// ---------------------------------------------------------------------------
// Safe wrappers.
// ---------------------------------------------------------------------------

/// Issue `ioctl(fd, request, &val)` where the request expects a pointer
/// to a single `c_int` written by userspace (an `_IOW(..., int)`).
pub fn ioctl_set_int(fd: BorrowedFd<'_>, request: libc::c_ulong, val: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` is a valid open file descriptor for the duration of
    // this call (`BorrowedFd` invariant). `request` was constructed with
    // `_IOW(..., int)`, so the kernel will read exactly `sizeof(int)`
    // bytes from `&val`. `val` lives on the stack and is initialized.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, &val) };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Issue `ioctl(fd, request, &mut buf)` where the request reads a `c_int`
/// from the kernel (an `_IOR(..., int)`).
pub fn ioctl_get_int(fd: BorrowedFd<'_>, request: libc::c_ulong) -> io::Result<libc::c_int> {
    let mut out: libc::c_int = 0;
    // SAFETY: `fd` is valid for the duration of the call. `request` was
    // constructed with `_IOR(..., int)`, so the kernel writes exactly
    // `sizeof(int)` bytes into `out`, which is properly aligned.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, &mut out) };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(out) }
}

/// Issue `ioctl(fd, request, &mut val)` for `_IOWR(..., int)` — value is
/// both input (e.g. requested unit number) and output (assigned number).
pub fn ioctl_xchg_int(
    fd: BorrowedFd<'_>,
    request: libc::c_ulong,
    val: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut io_val: libc::c_int = val;
    // SAFETY: `fd` is valid. `request` is `_IOWR(..., int)`, so the
    // kernel both reads and writes `sizeof(int)` bytes at `&mut io_val`.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, &mut io_val) };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(io_val) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the resolved ioctl numbers against the values produced by
    /// the kernel headers on `Linux/x86_64` (identical on `aarch64`;
    /// the macros are arch-agnostic for these requests because
    /// `sizeof(int) == 4` everywhere we care about).
    #[test]
    fn ioctl_numbers_match_kernel() {
        assert_eq!(PPPIOCGCHAN, 0x8004_7437);
        assert_eq!(PPPIOCATTCHAN, 0x4004_7438);
        assert_eq!(PPPIOCDISCONN, 0x0000_7439);
        assert_eq!(PPPIOCCONNECT, 0x4004_743a);
        assert_eq!(PPPIOCSMRRU, 0x4004_743b);
        assert_eq!(PPPIOCDETACH, 0x4004_743c);
        assert_eq!(PPPIOCATTACH, 0x4004_743d);
        assert_eq!(PPPIOCNEWUNIT, 0xc004_743e);
        assert_eq!(PPPIOCSNPMODE, 0x4008_744b);
        assert_eq!(PPPIOCSMRU, 0x4004_7453);
        assert_eq!(PPPIOCGUNIT, 0x8004_7456);
        assert_eq!(PPPIOCSFLAGS, 0x4004_7459);
        assert_eq!(PPPIOCGFLAGS, 0x8004_745a);
    }

    #[test]
    fn npioctl_size_is_two_ints() {
        assert_eq!(core::mem::size_of::<NpIoctl>(), 8);
    }
}
