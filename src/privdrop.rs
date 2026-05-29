//! Post-bind privilege drop for the daemon.
//!
//! Linux-specific. After the privileged operations are done (binding
//! `:443`, opening the control socket under `/run/`, loading the TLS
//! private key) the server switches to an unprivileged user while
//! retaining `CAP_NET_ADMIN` — every session still needs that
//! capability for the `/dev/ppp` ioctls and the netlink
//! `RTM_NEWADDR` / `RTM_NEWLINK` round-trip.
//!
//! Sequence (must run while the process is still single-threaded —
//! [`drop_to`] enforces that with a `debug_assert!`):
//!
//! 1. `prctl(PR_SET_KEEPCAPS, 1)` — `setuid` would otherwise wipe the
//!    permitted capability set when leaving uid 0.
//! 2. `setgroups([])` — drop supplementary groups.
//! 3. `setgid(target_gid)` then `setuid(target_uid)`.
//! 4. `capset` to a minimal set containing only the caps in
//!    `keep_caps`, in both the effective and permitted vectors;
//!    inheritable is cleared.
//!
//! This duplicates what systemd's `User=` + `AmbientCapabilities=
//! CAP_NET_ADMIN` provides for free, but is useful when running
//! outside systemd (containers, supervisord, bare init).

use std::ffi::{CStr, CString};
use std::io;
use std::mem::MaybeUninit;

use libc::{c_char, c_int, gid_t, uid_t};
use thiserror::Error;

/// Linux capability bit for `CAP_NET_ADMIN` (per `<linux/capability.h>`).
pub const CAP_NET_ADMIN: u32 = 12;

/// `_LINUX_CAPABILITY_VERSION_3`, the 64-bit-capable header version.
/// Two `cap_user_data_t` slots follow the header (low 32 bits, then
/// high 32 bits).
const CAP_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Debug, Error)]
pub enum DropError {
    #[error("user {0:?} not found")]
    UnknownUser(String),
    #[error("group {0:?} not found")]
    UnknownGroup(String),
    #[error("--user requires root (current euid={0})")]
    NotRoot(u32),
    #[error("{op} failed: {source}")]
    Syscall {
        op: &'static str,
        #[source]
        source: io::Error,
    },
}

impl DropError {
    fn syscall(op: &'static str) -> Self {
        Self::Syscall {
            op,
            source: io::Error::last_os_error(),
        }
    }
}

/// Resolved target identity for a drop.
#[derive(Debug, Clone, Copy)]
pub struct Identity {
    pub uid: uid_t,
    pub gid: gid_t,
}

/// Look up a user by name (no numeric-uid parsing — keep the CLI
/// surface narrow). Returns the user's uid + primary gid.
pub fn lookup_user(name: &str) -> Result<Identity, DropError> {
    let cname = CString::new(name).map_err(|_| DropError::UnknownUser(name.to_string()))?;
    let mut pwd: MaybeUninit<libc::passwd> = MaybeUninit::uninit();
    let mut buf = [0i8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r expects a NUL-terminated name, a passwd
    // output slot, a scratch buffer, the buffer length, and a result
    // double-pointer. All sized correctly above.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<c_char>(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 {
        return Err(DropError::Syscall {
            op: "getpwnam_r",
            source: io::Error::from_raw_os_error(rc),
        });
    }
    if result.is_null() {
        return Err(DropError::UnknownUser(name.to_string()));
    }
    // SAFETY: result == &pwd, getpwnam_r returned success.
    let pwd = unsafe { pwd.assume_init() };
    Ok(Identity {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
    })
}

/// Look up a group by name.
pub fn lookup_group(name: &str) -> Result<gid_t, DropError> {
    let cname = CString::new(name).map_err(|_| DropError::UnknownGroup(name.to_string()))?;
    let mut grp: MaybeUninit<libc::group> = MaybeUninit::uninit();
    let mut buf = [0i8; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: same shape as getpwnam_r above; getgrnam_r is the group
    // equivalent with the same calling convention.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            grp.as_mut_ptr(),
            buf.as_mut_ptr().cast::<c_char>(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 {
        return Err(DropError::Syscall {
            op: "getgrnam_r",
            source: io::Error::from_raw_os_error(rc),
        });
    }
    if result.is_null() {
        return Err(DropError::UnknownGroup(name.to_string()));
    }
    // SAFETY: result == &grp, getgrnam_r returned success.
    let grp = unsafe { grp.assume_init() };
    Ok(grp.gr_gid)
}

/// Look up the *username* for a uid (used only to log a friendly name
/// after the drop). Returns the input uid as a string on lookup
/// failure; never errors.
pub fn name_for_uid(uid: uid_t) -> String {
    let mut pwd: MaybeUninit<libc::passwd> = MaybeUninit::uninit();
    let mut buf = [0i8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: same calling convention as `lookup_user`, just keyed by uid.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<c_char>(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return uid.to_string();
    }
    // SAFETY: getpwuid_r succeeded and populated pwd; pw_name is a
    // borrowed pointer into `buf` that we copy out before returning.
    let pwd = unsafe { pwd.assume_init() };
    // SAFETY: pw_name is a NUL-terminated C string owned by `buf`.
    let cstr = unsafe { CStr::from_ptr(pwd.pw_name) };
    cstr.to_string_lossy().into_owned()
}

/// Drop the process to `id`, retaining the capabilities listed in
/// `keep`. Must be called while the process is single-threaded.
///
/// On success the running euid/egid/uid/gid all equal `id` and the
/// effective + permitted capability sets contain exactly `keep`.
pub fn drop_to(id: Identity, keep: &[u32]) -> Result<(), DropError> {
    // SAFETY: getuid()/geteuid() have no preconditions.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err(DropError::NotRoot(euid));
    }

    // Single-thread requirement. setuid() on Linux glibc broadcasts
    // to all threads via signals, which can race with anything those
    // threads are doing (RADIUS UDP, tokio reactor, etc.). Refuse to
    // run if other threads exist.
    debug_assert!(
        is_single_threaded(),
        "drop_to must be called before spawning any other threads"
    );

    // SAFETY: PR_SET_KEEPCAPS takes one int arg per `prctl(2)`. Zero
    // is the documented success return.
    let rc = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1_u64, 0_u64, 0_u64, 0_u64) };
    if rc != 0 {
        return Err(DropError::syscall("prctl(PR_SET_KEEPCAPS)"));
    }

    // SAFETY: setgroups with size=0 and a non-NULL but unused ptr is
    // well-defined per setgroups(2); pass a 1-element scratch slot to
    // satisfy "non-NULL" without UB.
    let empty: [gid_t; 1] = [0];
    let rc = unsafe { libc::setgroups(0, empty.as_ptr()) };
    if rc != 0 {
        return Err(DropError::syscall("setgroups"));
    }

    // SAFETY: setresgid/setresuid take three gid_t/uid_t scalars. We
    // set real, effective, and saved-set to the same target so a
    // future setuid(0) cannot regain privilege.
    let rc = unsafe { libc::setresgid(id.gid, id.gid, id.gid) };
    if rc != 0 {
        return Err(DropError::syscall("setresgid"));
    }
    let rc = unsafe { libc::setresuid(id.uid, id.uid, id.uid) };
    if rc != 0 {
        return Err(DropError::syscall("setresuid"));
    }

    // Build the capability bitmap. Linux capabilities are 64-bit
    // wide, split into two `CapData` slots in version-3 ABI.
    let mut low: u32 = 0;
    let mut high: u32 = 0;
    for &c in keep {
        if c < 32 {
            low |= 1 << c;
        } else {
            high |= 1 << (c - 32);
        }
    }
    let hdr = CapHeader {
        version: CAP_VERSION_3,
        pid: 0, // self
    };
    let data = [
        CapData {
            effective: low,
            permitted: low,
            inheritable: 0,
        },
        CapData {
            effective: high,
            permitted: high,
            inheritable: 0,
        },
    ];
    // SAFETY: capset takes a header pointer and a data pointer
    // (two-element array for version 3). Header version matches the
    // data array length.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &raw const hdr,
            data.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(DropError::syscall("capset"));
    }

    Ok(())
}

/// Approximate single-thread check via `/proc/self/status`. Cheap and
/// good enough for a startup-time `debug_assert!`. Returns `true` on
/// any I/O failure so we don't false-positive on exotic systems.
fn is_single_threaded() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return true;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            return rest.trim() == "1";
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_self_user_succeeds() {
        // SAFETY: geteuid is signal-safe and takes no args.
        let me = unsafe { libc::geteuid() };
        let name = name_for_uid(me);
        // Round-trip: lookup by name should give back the same uid.
        // (Skip the assertion if name_for_uid fell back to the
        // numeric form because /etc/passwd is unusual in this env.)
        if let Ok(id) = lookup_user(&name) {
            assert_eq!(id.uid, me);
        }
    }

    #[test]
    fn lookup_missing_user_reports_unknown() {
        let err = lookup_user("definitely-no-such-user-xyz-quux-42").unwrap_err();
        assert!(matches!(err, DropError::UnknownUser(_)), "{err:?}");
    }

    #[test]
    fn drop_to_rejects_non_root() {
        // SAFETY: geteuid is signal-safe.
        let me = unsafe { libc::geteuid() };
        if me == 0 {
            // Running as root in some CI envs — skip; the negative
            // path can't be exercised here.
            return;
        }
        let id = Identity { uid: me, gid: 0 };
        let err = drop_to(id, &[CAP_NET_ADMIN]).unwrap_err();
        assert!(matches!(err, DropError::NotRoot(_)), "{err:?}");
    }
}
