//! Shared `NETLINK_*` primitives.
//!
//! One hand-rolled netlink stack for every consumer in the tree:
//!
//! - [`crate::kppp::netlink`] — `NETLINK_ROUTE` for `pppN` /
//!   `tun` bring-up (`RTM_NEWADDR`, `RTM_NEWLINK`, `RTM_GETLINK`
//!   for `IFLA_STATS64`).
//! - [`crate::shape::netlink`] — `NETLINK_ROUTE` for `tc`
//!   (`RTM_NEWQDISC`, `RTM_NEWTCLASS`, `RTM_NEWTFILTER`).
//! - [`crate::shape::mss`] — `NETLINK_NETFILTER` for nf_tables MSS
//!   clamping.
//!
//! All three previously carried near-duplicate copies of the wire
//! builder, the `socket(2) + bind(2) + send + recv` wrapper, and the
//! ACK draining loop. They live here now; the per-consumer modules
//! contribute only the family-specific message shapes and the
//! higher-level operations they expose.
//!
//! Why hand-rolled instead of the `rtnetlink` / `netlink-packet-*`
//! crates: three message families with a handful of attribute types
//! each is a small enough surface that the dependency tree is not
//! worth carrying. These are session-bring-up / session-teardown
//! operations, not a hot path; a synchronous `send`/`recv` against a
//! blocking socket is the right shape. Keeps the `unsafe` surface
//! tiny and explicit — only the `libc::socket` / `sendto` / `recv`
//! calls plus a couple of pointer reads on the ACK path.
//!
//! ## References
//!
//! - netlink(7), rtnetlink(7) — wire format and ACK semantics.
//! - `<linux/netlink.h>` — `nlmsghdr`, `nlattr`, `NLM_F_*`.
//! - `<linux/rtnetlink.h>`, `<linux/if_addr.h>`, `<linux/if_link.h>`,
//!   `<linux/pkt_sched.h>`, `<linux/pkt_cls.h>`,
//!   `<linux/netfilter/nfnetlink.h>` — per-family constants and
//!   message layouts.

// Casting `libc` constants (`AF_NETLINK`, `NLA_F_NESTED`, …) and
// `usize` sizes into the smaller integer types the wire format
// demands is unavoidable in a hand-rolled netlink client and the
// values involved are constants well within the target range.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::doc_markdown // pppN / nf_tables / socket(2) etc. are intentional prose, not Rust identifiers.
)]

use std::collections::HashSet;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// ---------------------------------------------------------------------------
// Netlink message-flag bits. `libc` does not export NLM_F_*.
// ---------------------------------------------------------------------------

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

pub const NLMSG_ERROR: u16 = 2;
#[allow(dead_code)] // FUTURE: end-of-multipart marker for `NLM_F_DUMP` consumers (not used by single-message acks).
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_HDRLEN: usize = mem::size_of::<libc::nlmsghdr>();

/// View a POD `T: Copy` as its raw byte representation.
#[must_use]
pub fn bytes_of<T: Copy>(value: &T) -> &[u8] {
    // SAFETY: `T: Copy` is the closest stable approximation to
    // "POD". Every caller passes `#[repr(C)]` structs whose byte
    // representation is the wire format. The slice covers exactly
    // `size_of::<T>()` bytes of an owned reference.
    unsafe {
        std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), mem::size_of::<T>())
    }
}

/// Round a netlink message length up to the next 4-byte boundary
/// per `<linux/netlink.h>` `NLMSG_ALIGN`.
#[must_use]
pub const fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Nlattr {
    nla_len: u16,
    nla_type: u16,
}

// ---------------------------------------------------------------------------
// Message construction.
// ---------------------------------------------------------------------------

/// Wire-format buffer for a single netlink request.
///
/// Layout: one outermost `nlmsghdr` at byte 0 (patched in
/// [`finalize`](MessageBuf::finalize)), followed by a family-specific
/// payload (e.g. `tcmsg` for rtnetlink, `nfgenmsg` for nf_tables,
/// `ifaddrmsg` / `ifinfomsg` for `pppN` bring-up), followed by a flat
/// or nested attribute tree.
///
/// `nest_begin` always sets `NLA_F_NESTED` on the attr type. The
/// kernel parsers strip the flag before lookup in both rtnetlink
/// and nf_tables paths, so it is always safe; modern iproute2
/// likewise sets it unconditionally.
pub struct MessageBuf {
    bytes: Vec<u8>,
    /// Stack of byte offsets pointing to currently-open nested
    /// `nlattr` headers; each entry is the offset of the `nla_len`
    /// field that needs patching at the matching `nest_end`.
    nest_stack: Vec<usize>,
    /// `nlmsghdr.nlmsg_seq` of the request. Cached at build time so
    /// callers (notably the nf_tables batch envelope) can record
    /// expected acks without re-reading the header bytes.
    seq: u32,
    /// `nlmsghdr.nlmsg_flags` of the request. Same rationale as `seq`.
    flags: u16,
}

impl MessageBuf {
    /// Allocate a fresh buffer and emplace the outer `nlmsghdr`.
    /// `nlmsg_len` is patched on [`finalize`](Self::finalize); the
    /// rest of the header is final.
    #[must_use]
    pub fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        let mut this = Self {
            bytes: Vec::with_capacity(512),
            nest_stack: Vec::with_capacity(4),
            seq,
            flags,
        };
        let hdr = libc::nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        this.bytes.extend_from_slice(bytes_of(&hdr));
        this
    }

    /// Sequence number passed to [`Self::new`]. Used by the
    /// nf_tables batch envelope to record per-message expected
    /// acks without re-parsing the header bytes.
    #[must_use]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Flags passed to [`Self::new`].
    #[must_use]
    #[allow(dead_code)] // FUTURE: nf_tables batch builder reads this back when assembling envelopes.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Final wire bytes after [`Self::finalize`] — for `sendto`.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Append a `#[repr(C)]` POD struct, padded to the next 4-byte
    /// boundary. Used for family-specific headers (`tcmsg`,
    /// `nfgenmsg`, `ifaddrmsg`, `ifinfomsg`, …) that follow the
    /// outer `nlmsghdr`.
    pub fn push_struct<T: Copy>(&mut self, value: &T) {
        self.bytes.extend_from_slice(bytes_of(value));
        self.pad_to_4();
    }

    /// Push a flat (non-nested) attribute with raw payload bytes.
    /// Padded to 4-byte alignment after the payload.
    pub fn push_attr_bytes(&mut self, attr_type: u16, payload: &[u8]) {
        let total = mem::size_of::<Nlattr>() + payload.len();
        let hdr = Nlattr {
            nla_len: u16::try_from(total).expect("attribute too large"),
            nla_type: attr_type,
        };
        self.bytes.extend_from_slice(bytes_of(&hdr));
        self.bytes.extend_from_slice(payload);
        self.pad_to_4();
    }

    /// Convenience for a single-byte attribute.
    #[allow(dead_code)] // FUTURE: nf_tables expression operands.
    pub fn push_attr_u8(&mut self, attr_type: u16, value: u8) {
        self.push_attr_bytes(attr_type, &[value]);
    }

    /// Push a `__be32` attribute. nf_tables reads every "u32"
    /// attribute with `ntohl(nla_get_be32(...))` — hook num /
    /// priority, chain policy, every expression register & op
    /// code, `NFTA_EXTHDR_*`, …  — even though the netlink policy
    /// is declared `NLA_U32`. Always emit big-endian on the wire.
    /// rtnetlink's tc consumers don't use this helper; they emit
    /// native-byte-order u32s through [`Self::push_attr_bytes`].
    pub fn push_attr_be32(&mut self, attr_type: u16, value: u32) {
        self.push_attr_bytes(attr_type, &value.to_be_bytes());
    }

    /// Convenience for a NUL-terminated string attribute.
    pub fn push_attr_cstr(&mut self, attr_type: u16, value: &CStr) {
        self.push_attr_bytes(attr_type, value.to_bytes_with_nul());
    }

    /// Begin a nested attribute. Subsequent `push_attr_*` /
    /// `push_struct` calls go inside; close with [`Self::nest_end`].
    pub fn nest_begin(&mut self, attr_type: u16) {
        let off = self.bytes.len();
        self.nest_stack.push(off);
        let hdr = Nlattr {
            nla_len: 0, // patched in nest_end
            nla_type: attr_type | (libc::NLA_F_NESTED as u16),
        };
        self.bytes.extend_from_slice(bytes_of(&hdr));
    }

    /// Close the most recent [`Self::nest_begin`] and patch its length.
    pub fn nest_end(&mut self) {
        let off = self.nest_stack.pop().expect("nest_end without nest_begin");
        let len = u16::try_from(self.bytes.len() - off).expect("nested attribute too large");
        self.bytes[off..off + 2].copy_from_slice(&len.to_ne_bytes());
        // Re-pad in case the inner payload's last attribute did not
        // end on a 4-byte boundary. Idempotent when already aligned.
        self.pad_to_4();
    }

    /// Patch the outer `nlmsg_len` field in place. After this call
    /// the buffer is ready for `sendto`.
    pub fn finalize(&mut self) {
        assert!(
            self.nest_stack.is_empty(),
            "MessageBuf::finalize with {} unclosed nests",
            self.nest_stack.len(),
        );
        let len = u32::try_from(self.bytes.len()).expect("message too large");
        self.bytes[..4].copy_from_slice(&len.to_ne_bytes());
    }

    fn pad_to_4(&mut self) {
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Socket wrapper.
// ---------------------------------------------------------------------------

/// Synchronous `NETLINK_*` socket wrapper. One request → one or
/// more `NLMSG_ERROR` acks at a time; never used to dump.
#[derive(Debug)]
pub struct NetlinkSocket {
    fd: OwnedFd,
}

impl NetlinkSocket {
    /// `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, family) +
    /// bind(2)` against a kernel-pid sockaddr.
    pub fn open(family: i32) -> io::Result<Self> {
        // SAFETY: standard socket(2) FFI; checked for -1.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                family,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly-opened fd we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: zeroed sockaddr_nl is a valid kernel-pid-zero
        // bind address; field types are POD.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: addr is initialized; its length is passed
        // explicitly; fd is valid.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// `sendto(2)` the entire `bytes` slice to the kernel, failing
    /// on any short write.
    pub fn send(&self, bytes: &[u8]) -> io::Result<()> {
        // SAFETY: zeroed sockaddr_nl is valid; nl_family set
        // before use; size passed explicitly.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: `bytes` is a valid initialized slice; `addr`
        // describes the kernel peer (nl_pid = 0).
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                std::ptr::addr_of!(addr).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if (sent as usize) != bytes.len() {
            return Err(io::Error::other(format!(
                "short netlink send: {sent} of {} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }

    /// `recv(2)` one datagram, returning the populated prefix of
    /// `buf`.
    pub fn recv_into<'a>(&self, buf: &'a mut [u8]) -> io::Result<&'a [u8]> {
        // SAFETY: `buf` is a valid writable byte slice.
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(&buf[..n as usize])
    }
}

// ---------------------------------------------------------------------------
// Ack draining.
// ---------------------------------------------------------------------------

/// Reasons [`drain_acks`] can fail. Translated to the caller's
/// concrete error type at the boundary.
#[derive(Debug)]
pub enum DrainError {
    /// Reply truncated mid-`nlmsghdr` or mid-payload.
    Truncated,
    /// The kernel returned a non-zero `-errno` payload on an
    /// `NLMSG_ERROR` reply. Value is the positive errno.
    Kernel(i32),
}

/// Walk every `nlmsghdr` in `buf`. For each `NLMSG_ERROR`:
/// - `err == 0` removes the matching seq from `remaining`.
/// - `err != 0` short-circuits with [`DrainError::Kernel`].
///
/// Other message types (notifications, multicast events, replies
/// the caller did not request) are ignored. Suitable for both the
/// single-message rtnetlink case (`remaining` starts as a 1-element
/// set) and the nf_tables batch case (one ack per inner message
/// carrying `NLM_F_ACK`).
pub fn drain_acks(buf: &[u8], remaining: &mut HashSet<u32>) -> Result<(), DrainError> {
    let mut offset = 0usize;
    while offset + NLMSG_HDRLEN <= buf.len() {
        // SAFETY: bounds-checked above; nlmsghdr is POD.
        let hdr =
            unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr().cast::<libc::nlmsghdr>()) };
        let msg_len = usize::try_from(hdr.nlmsg_len).unwrap_or(0);
        if msg_len < NLMSG_HDRLEN || offset + msg_len > buf.len() {
            return Err(DrainError::Truncated);
        }
        if hdr.nlmsg_type == NLMSG_ERROR {
            if msg_len < NLMSG_HDRLEN + 4 {
                return Err(DrainError::Truncated);
            }
            let mut err_bytes = [0u8; 4];
            err_bytes.copy_from_slice(&buf[offset + NLMSG_HDRLEN..offset + NLMSG_HDRLEN + 4]);
            let err = i32::from_ne_bytes(err_bytes);
            if err != 0 {
                return Err(DrainError::Kernel(-err));
            }
            remaining.remove(&hdr.nlmsg_seq);
        }
        offset += nlmsg_align(msg_len);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlmsg_len_patched_on_finalize() {
        let mut buf = MessageBuf::new(36 /* RTM_NEWQDISC */, NLM_F_REQUEST | NLM_F_ACK, 1);
        buf.push_attr_bytes(1 /* TCA_KIND */, b"htb\0");
        buf.finalize();
        let len = u32::from_ne_bytes(buf.bytes()[0..4].try_into().unwrap());
        assert_eq!(len as usize, buf.bytes().len());
    }

    #[test]
    fn nest_begin_end_patches_length() {
        let mut buf = MessageBuf::new(36, NLM_F_REQUEST, 1);
        buf.nest_begin(2 /* TCA_OPTIONS */);
        buf.push_attr_bytes(1, &[0u8; 8]);
        buf.nest_end();
        buf.finalize();
        let nest_len = u16::from_ne_bytes(buf.bytes()[16..18].try_into().unwrap());
        // Outer attr (4 B header) + inner attr (4 B header + 8 B payload) = 16.
        assert_eq!(nest_len, 16);
    }

    #[test]
    fn nest_begin_sets_nla_f_nested_flag() {
        let mut buf = MessageBuf::new(36, NLM_F_REQUEST, 1);
        buf.nest_begin(2);
        buf.nest_end();
        buf.finalize();
        // Bytes [16..18] = nla_len, [18..20] = nla_type | NLA_F_NESTED.
        let nla_type = u16::from_ne_bytes(buf.bytes()[18..20].try_into().unwrap());
        assert_eq!(nla_type, 2 | (libc::NLA_F_NESTED as u16));
    }

    #[test]
    fn drain_acks_consumes_seq_on_zero_err() {
        // Hand-craft an NLMSG_ERROR(err=0) for seq=42.
        let mut reply = Vec::new();
        let hdr = libc::nlmsghdr {
            nlmsg_len: (NLMSG_HDRLEN + 4) as u32,
            nlmsg_type: NLMSG_ERROR,
            nlmsg_flags: 0,
            nlmsg_seq: 42,
            nlmsg_pid: 0,
        };
        reply.extend_from_slice(bytes_of(&hdr));
        reply.extend_from_slice(&0i32.to_ne_bytes());

        let mut remaining: HashSet<u32> = [42].into_iter().collect();
        drain_acks(&reply, &mut remaining).expect("ack");
        assert!(remaining.is_empty());
    }

    #[test]
    fn drain_acks_surfaces_nonzero_err() {
        let mut reply = Vec::new();
        let hdr = libc::nlmsghdr {
            nlmsg_len: (NLMSG_HDRLEN + 4) as u32,
            nlmsg_type: NLMSG_ERROR,
            nlmsg_flags: 0,
            nlmsg_seq: 7,
            nlmsg_pid: 0,
        };
        reply.extend_from_slice(bytes_of(&hdr));
        reply.extend_from_slice(&(-libc::EEXIST).to_ne_bytes());

        let mut remaining: HashSet<u32> = [7].into_iter().collect();
        match drain_acks(&reply, &mut remaining) {
            Err(DrainError::Kernel(errno)) => assert_eq!(errno, libc::EEXIST),
            other => panic!("expected Kernel(EEXIST), got {other:?}"),
        }
    }
}
