//! Minimal `NETLINK_ROUTE` client for `tc` operations.
//!
//! Sister of [`crate::kppp::netlink`], scoped to the
//! `RTM_*QDISC` / `RTM_*TCLASS` / `RTM_*TFILTER` message types. Same
//! posture: hand-rolled wire format against `<linux/pkt_sched.h>`,
//! synchronous send/recv against a blocking socket, no external
//! crates beyond `libc`.
//!
//! Why not reuse [`crate::kppp::netlink::RtNetlink`] directly: that
//! type's [`MessageBuf`] / [`exchange`] surface is private to the
//! `kppp` module and grew up around `RTM_NEWADDR` / `RTM_NEWLINK`
//! shapes. Promoting it would expand the `kppp` API surface for one
//! adjacent consumer; keeping a small, focused mirror here is
//! cheaper to maintain and avoids cross-module coupling on the
//! steady-state code path's neighbour.
//!
//! ## Scope
//!
//! Today: send a single message + read its `NLMSG_ERROR` ack.
//! Sufficient for `RTM_NEWQDISC` (HTB root install) and
//! `RTM_NEWTCLASS` (HTB leaf class install).
//!
//! FUTURE: dump (`NLM_F_DUMP`) responses for `Shaper::clear` to
//! enumerate already-installed qdiscs, and `RTM_NEWTFILTER` for the
//! ingress policer.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
)]

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::ShapeError;

// ---------------------------------------------------------------------------
// Netlink message-flag bits we use. `libc` does not export NLM_F_*.
// ---------------------------------------------------------------------------

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_REPLACE: u16 = 0x100;

const NLMSG_ERROR: u16 = 2;
const NLMSG_HDRLEN: usize = mem::size_of::<libc::nlmsghdr>();

// ---------------------------------------------------------------------------
// Socket wrapper.
// ---------------------------------------------------------------------------

/// `NETLINK_ROUTE` socket scoped to traffic-control work. One
/// request → one ack at a time; never used to dump.
#[derive(Debug)]
pub struct TcNetlink {
    fd: OwnedFd,
    seq: u32,
}

impl TcNetlink {
    pub fn open() -> Result<Self, ShapeError> {
        // SAFETY: standard socket(2) FFI; checked for -1.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(ShapeError::Netlink(io::Error::last_os_error()));
        }
        // SAFETY: `raw` is a freshly-opened fd we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: zeroed sockaddr_nl is a valid kernel-pid-zero
        // bind address; field types are POD.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: addr is a valid initialized sockaddr_nl whose
        // length we pass explicitly; fd is valid.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(ShapeError::Netlink(io::Error::last_os_error()));
        }

        Ok(Self { fd, seq: 1 })
    }

    /// Allocate the next sequence number for the netlink header.
    pub fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Send a fully-built request (already finalized via
    /// [`MessageBuf::finalize`]) and read its single-message ack.
    /// Maps the kernel's `-errno` payload onto
    /// [`ShapeError::Kernel`].
    pub fn exchange(&self, op: &'static str, buf: &MessageBuf) -> Result<(), ShapeError> {
        // SAFETY: zeroed sockaddr_nl is valid; nl_family is set
        // before use; we pass exact size to sendto.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: buf.bytes is a valid initialized slice; addr
        // describes the kernel (nl_pid = 0).
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.bytes.as_ptr().cast(),
                buf.bytes.len(),
                0,
                std::ptr::addr_of!(addr).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(ShapeError::Netlink(io::Error::last_os_error()));
        }

        let mut reply = [0u8; 4096];
        // SAFETY: reply is a valid &mut [u8].
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                reply.as_mut_ptr().cast(),
                reply.len(),
                0,
            )
        };
        if n < 0 {
            return Err(ShapeError::Netlink(io::Error::last_os_error()));
        }
        parse_ack(op, &reply[..n as usize])
    }
}

fn parse_ack(op: &'static str, buf: &[u8]) -> Result<(), ShapeError> {
    if buf.len() < NLMSG_HDRLEN {
        return Err(ShapeError::Netlink(io::Error::other("short netlink ack")));
    }
    // SAFETY: bounds-checked above; nlmsghdr is plain-old-data
    // valid for any byte pattern.
    let hdr: libc::nlmsghdr =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::nlmsghdr>()) };
    if hdr.nlmsg_type != NLMSG_ERROR {
        return Err(ShapeError::Netlink(io::Error::other(format!(
            "{op}: unexpected reply type {}",
            hdr.nlmsg_type
        ))));
    }
    if buf.len() < NLMSG_HDRLEN + 4 {
        return Err(ShapeError::Netlink(io::Error::other(
            "truncated NLMSG_ERROR",
        )));
    }
    // Payload starts with a signed `int error`; 0 means success ack.
    let mut err_bytes = [0u8; 4];
    err_bytes.copy_from_slice(&buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]);
    let err = i32::from_ne_bytes(err_bytes);
    if err == 0 {
        Ok(())
    } else {
        Err(ShapeError::Kernel { op, errno: -err })
    }
}

// ---------------------------------------------------------------------------
// Message construction.
// ---------------------------------------------------------------------------

/// Wire-format buffer for a single netlink request. Tracks the
/// outermost `nlmsghdr` offset so it can patch `nlmsg_len` at
/// finalize, plus a stack of nested `rtattr` open-brackets so
/// callers can `nest_begin` / `nest_end` without bookkeeping.
pub struct MessageBuf {
    pub bytes: Vec<u8>,
    hdr_offset: usize,
    /// Stack of byte offsets pointing to currently-open nested
    /// rtattr headers. Each entry is the offset of the `rta_len`
    /// field that needs patching at the matching `nest_end`.
    nest_stack: Vec<usize>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rtattr {
    rta_len: u16,
    rta_type: u16,
}

impl MessageBuf {
    pub fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(512),
            hdr_offset: 0,
            nest_stack: Vec::with_capacity(2),
        }
    }

    pub fn push_nlmsghdr(&mut self, msg_type: u16, flags: u16, seq: u32) {
        self.hdr_offset = self.bytes.len();
        let hdr = libc::nlmsghdr {
            nlmsg_len: 0, // patched in finalize()
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        self.push_struct(&hdr);
    }

    pub fn push_struct<T: Copy>(&mut self, value: &T) {
        // SAFETY: `T: Copy` is the closest stable approximation to
        // "POD" for our purposes; the caller passes `#[repr(C)]`
        // structs whose byte representation is the wire format.
        let bytes = unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), mem::size_of::<T>())
        };
        self.bytes.extend_from_slice(bytes);
        self.pad_to_4();
    }

    /// Push a flat (non-nested) attribute with raw payload bytes.
    pub fn push_attr(&mut self, attr_type: u16, payload: &[u8]) {
        let total = 4 + payload.len();
        let hdr = Rtattr {
            rta_len: u16::try_from(total).expect("attribute too large"),
            rta_type: attr_type,
        };
        self.push_raw_struct(&hdr);
        self.bytes.extend_from_slice(payload);
        self.pad_to_4();
    }

    /// Begin a nested attribute. Subsequent `push_attr` /
    /// `push_struct` calls go inside; close with `nest_end`.
    pub fn nest_begin(&mut self, attr_type: u16) {
        let off = self.bytes.len();
        self.nest_stack.push(off);
        let hdr = Rtattr {
            rta_len: 0, // patched in nest_end
            rta_type: attr_type,
        };
        self.push_raw_struct(&hdr);
    }

    pub fn nest_end(&mut self) {
        let off = self.nest_stack.pop().expect("nest_end without nest_begin");
        let len = u16::try_from(self.bytes.len() - off).expect("nested attribute too large");
        self.bytes[off..off + 2].copy_from_slice(&len.to_ne_bytes());
    }

    pub fn finalize(&mut self) {
        assert!(
            self.nest_stack.is_empty(),
            "MessageBuf::finalize with {} unclosed nests",
            self.nest_stack.len(),
        );
        let len = u32::try_from(self.bytes.len() - self.hdr_offset).expect("message too large");
        self.bytes[self.hdr_offset..self.hdr_offset + 4].copy_from_slice(&len.to_ne_bytes());
    }

    fn push_raw_struct<T: Copy>(&mut self, value: &T) {
        // SAFETY: same invariant as `push_struct`.
        let bytes = unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), mem::size_of::<T>())
        };
        self.bytes.extend_from_slice(bytes);
        // Note: deliberately *not* padding here. Callers control
        // when alignment matters via `pad_to_4`.
    }

    fn pad_to_4(&mut self) {
        while self.bytes.len() % 4 != 0 {
            self.bytes.push(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlmsg_len_patched_on_finalize() {
        let mut buf = MessageBuf::new();
        buf.push_nlmsghdr(36 /* RTM_NEWQDISC */, NLM_F_REQUEST | NLM_F_ACK, 1);
        buf.push_attr(1 /* TCA_KIND */, b"htb\0");
        buf.finalize();
        // First 4 bytes = nlmsg_len, native-endian u32.
        let len = u32::from_ne_bytes(buf.bytes[0..4].try_into().unwrap());
        assert_eq!(len as usize, buf.bytes.len());
    }

    #[test]
    fn nest_begin_end_patches_length() {
        let mut buf = MessageBuf::new();
        buf.push_nlmsghdr(36, NLM_F_REQUEST, 1);
        buf.nest_begin(2 /* TCA_OPTIONS */);
        buf.push_attr(1, &[0u8; 8]);
        buf.nest_end();
        buf.finalize();
        // The nested rtattr starts right after the nlmsghdr (16 B).
        let nest_len = u16::from_ne_bytes(buf.bytes[16..18].try_into().unwrap());
        // Outer attr (4 B header) + inner attr (4 B header + 8 B payload) = 16.
        assert_eq!(nest_len, 16);
    }
}
