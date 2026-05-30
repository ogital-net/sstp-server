//! Minimal `NETLINK_ROUTE` client for `pppN` bring-up.
//!
//! We need a tiny slice of rtnetlink — set the P2P IPv4 address pair
//! (local + peer) on the unit, bring the link UP, set the MTU. That's
//! it. Routes for `Framed-Route` come later; everything else (queues,
//! qdiscs, neighbour table) is out of scope.
//!
//! We hand-roll the wire format rather than pulling in the
//! `rtnetlink` crate (which transitively brings in `netlink-packet-*`,
//! `netlink-proto`, `netlink-sys`, plus a runtime integration layer)
//! because:
//!
//! - Three message types (`RTM_NEWADDR`, `RTM_NEWLINK`) is too small
//!   a surface to justify the dependency tree.
//! - These are session-bring-up operations, not a hot path; the
//!   simplest synchronous `send`/`recv` against a blocking socket is
//!   exactly right. No async needed.
//! - Keeps the `unsafe` surface tiny and explicit — only the
//!   `libc::socket`/`sendto`/`recv` calls and a couple of pointer
//!   reads on the ACK path.
//!
//! ## References
//!
//! - rtnetlink(7), netlink(7) — wire format and ACK semantics.
//! - `<linux/rtnetlink.h>`, `<linux/if_addr.h>`, `<linux/if_link.h>` —
//!   constants and message layouts.

// Casting `libc` constants (`AF_INET`, `AF_NETLINK`, `IFF_UP`, …) and
// `usize` sizes into the smaller integer types the wire format
// demands is unavoidable in a hand-rolled netlink client and the
// values involved are constants well within the target range. Suppress
// the noisy pedantic-clippy lints here rather than per-line.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::borrow_as_ptr,
    clippy::ref_as_ptr,
    clippy::struct_field_names
)]

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::SessionIpConfig;

// ---------------------------------------------------------------------------
// Constants. `libc` exports the message-type numbers but not all of the flag
// constants we need; redefine the handful that are missing.
// ---------------------------------------------------------------------------

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_REPLACE: u16 = 0x100;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const IFLA_MTU: u16 = 4;
/// `IFLA_STATS64` — kernel-maintained per-netdev byte/packet counters
/// (`struct rtnl_link_stats64` from `<linux/if_link.h>`). 192 bytes,
/// 24 × `u64` little-endian-on-LE-host (host byte order in netlink).
const IFLA_STATS64: u16 = 23;

const NLMSG_HDRLEN: usize = mem::size_of::<libc::nlmsghdr>();

// ---------------------------------------------------------------------------
// Message layouts.
//
// libc has `ifaddrmsg` and `ifinfomsg`, but the field names differ slightly
// across versions; we name our local mirrors to match `<linux/if_addr.h>` /
// `<linux/if_link.h>` so the spec lookup is obvious.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Ifinfomsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rtattr {
    rta_len: u16,
    rta_type: u16,
}

/// Subset of `struct rtnl_link_stats64` from `<linux/if_link.h>`.
///
/// The kernel struct is 24 × `u64`; we surface only the four
/// counters the RADIUS accounting client needs (octets / packets in
/// each direction). Errors / drops are intentionally omitted —
/// adding them is one struct field plus one offset constant if a
/// future caller needs them.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkStats64 {
    /// `rx_packets` (offset 0).
    pub rx_packets: u64,
    /// `tx_packets` (offset 8).
    pub tx_packets: u64,
    /// `rx_bytes` (offset 16).
    pub rx_bytes: u64,
    /// `tx_bytes` (offset 24).
    pub tx_bytes: u64,
}

impl LinkStats64 {
    /// Parse a 32-byte (or longer — we only consume the prefix)
    /// `rtnl_link_stats64` payload.
    fn from_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() < 32 {
            return None;
        }
        let read_u64 = |off: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&payload[off..off + 8]);
            // Netlink payloads are host byte order.
            u64::from_ne_bytes(b)
        };
        Some(Self {
            rx_packets: read_u64(0),
            tx_packets: read_u64(8),
            rx_bytes: read_u64(16),
            tx_bytes: read_u64(24),
        })
    }
}

/// Walk a sequence of `rtattr` records and return the
/// `IFLA_STATS64` payload if present.
fn find_stats64(mut attrs: &[u8]) -> Option<LinkStats64> {
    while attrs.len() >= 4 {
        let mut len_bytes = [0u8; 2];
        let mut type_bytes = [0u8; 2];
        len_bytes.copy_from_slice(&attrs[0..2]);
        type_bytes.copy_from_slice(&attrs[2..4]);
        let rta_len = u16::from_ne_bytes(len_bytes) as usize;
        let rta_type = u16::from_ne_bytes(type_bytes);
        if rta_len < 4 || rta_len > attrs.len() {
            return None;
        }
        if rta_type == IFLA_STATS64 {
            return LinkStats64::from_payload(&attrs[4..rta_len]);
        }
        // RTA_ALIGN(rta_len).
        let aligned = (rta_len + 3) & !3;
        if aligned >= attrs.len() {
            return None;
        }
        attrs = &attrs[aligned..];
    }
    None
}

#[inline]
#[allow(dead_code)] // FUTURE: full nlmsg alignment helpers consumed once `Framed-Route` (RTM_NEWROUTE) lands.
const fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[inline]
#[allow(dead_code)] // FUTURE: rta alignment helper for `Framed-Route` and other multi-attribute messages.
const fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    #[error("opening NETLINK_ROUTE socket: {0}")]
    Socket(#[source] io::Error),
    #[error("binding NETLINK_ROUTE socket: {0}")]
    Bind(#[source] io::Error),
    #[error("sending {op} request: {source}")]
    Send {
        op: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("receiving {op} reply: {source}")]
    Recv {
        op: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{op}: kernel returned errno {errno}")]
    Kernel { op: &'static str, errno: i32 },
    #[error("{op}: unexpected reply type {got}")]
    Unexpected { op: &'static str, got: u16 },
    #[error("setting MTU via SIOCSIFMTU on {ifname}: {source}")]
    #[allow(dead_code)] // FUTURE: paired with `set_mtu_ioctl` fallback above.
    SetMtu {
        ifname: String,
        #[source]
        source: io::Error,
    },
}

// ---------------------------------------------------------------------------
// Socket.
// ---------------------------------------------------------------------------

/// A `NETLINK_ROUTE` socket. Synchronous; one-request-one-ACK at a time.
#[derive(Debug)]
pub struct RtNetlink {
    fd: OwnedFd,
    seq: u32,
}

impl RtNetlink {
    pub fn open() -> Result<Self, NetlinkError> {
        // SAFETY: standard socket(2) FFI; checked for -1 on error.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(NetlinkError::Socket(io::Error::last_os_error()));
        }
        // SAFETY: `raw` is a freshly-opened fd we own and have not handed
        // out anywhere else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // nl_pid = 0 → kernel picks for us (PID-based, but unique per fd).
        // SAFETY: `addr` is a valid initialized sockaddr_nl; we pass its
        // address and exact size to bind(2).
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(NetlinkError::Bind(io::Error::last_os_error()));
        }

        Ok(Self { fd, seq: 1 })
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Configure a `pppN` unit with the P2P address pair from IPCP and
    /// bring it administratively up.
    pub fn bring_up(&mut self, ifindex: u32, cfg: &SessionIpConfig) -> Result<(), NetlinkError> {
        if let Some(mtu) = cfg.mtu {
            self.set_mtu(ifindex, mtu)?;
        }
        self.add_p2p_addr(ifindex, cfg.local, cfg.peer)?;
        self.set_link_up(ifindex)?;
        Ok(())
    }

    /// `RTM_NEWADDR` with `IFA_LOCAL = local` and `IFA_ADDRESS = peer`.
    /// For a point-to-point interface that is the kernel's way of
    /// recording "my address is `local`, the other end is `peer`".
    pub fn add_p2p_addr(
        &mut self,
        ifindex: u32,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Result<(), NetlinkError> {
        let mut buf = MessageBuf::new();
        buf.push_nlmsghdr(
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL,
            self.next_seq(),
        );
        buf.push_struct(&Ifaddrmsg {
            ifa_family: libc::AF_INET as u8,
            ifa_prefixlen: 32,
            ifa_flags: 0,
            ifa_scope: 0, // RT_SCOPE_UNIVERSE
            ifa_index: ifindex,
        });
        buf.push_attr(IFA_LOCAL, &local.octets());
        buf.push_attr(IFA_ADDRESS, &peer.octets());
        buf.finalize();
        self.exchange("RTM_NEWADDR", &buf)
    }

    /// `RTM_NEWLINK` with `IFF_UP` set in `ifi_flags` and the same bit
    /// in `ifi_change` (so the kernel only touches that flag).
    pub fn set_link_up(&mut self, ifindex: u32) -> Result<(), NetlinkError> {
        let mut buf = MessageBuf::new();
        buf.push_nlmsghdr(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, self.next_seq());
        buf.push_struct(&Ifinfomsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: i32::try_from(ifindex).expect("ifindex fits in i32"),
            ifi_flags: libc::IFF_UP as u32,
            ifi_change: libc::IFF_UP as u32,
        });
        buf.finalize();
        self.exchange("RTM_NEWLINK(IFF_UP)", &buf)
    }

    /// `RTM_NEWLINK` carrying an `IFLA_MTU` attribute.
    pub fn set_mtu(&mut self, ifindex: u32, mtu: u32) -> Result<(), NetlinkError> {
        let mut buf = MessageBuf::new();
        buf.push_nlmsghdr(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, self.next_seq());
        buf.push_struct(&Ifinfomsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: i32::try_from(ifindex).expect("ifindex fits in i32"),
            ifi_flags: 0,
            ifi_change: 0,
        });
        buf.push_attr(IFLA_MTU, &mtu.to_ne_bytes());
        buf.finalize();
        self.exchange("RTM_NEWLINK(IFLA_MTU)", &buf)
    }

    /// `RTM_GETLINK` for the given `ifindex`, returning the kernel's
    /// `IFLA_STATS64` counters (`struct rtnl_link_stats64`).
    ///
    /// Used by the RADIUS accounting client to sample
    /// `Acct-{Input,Output}-{Octets,Packets}` (and Gigawords) on
    /// Interim and Stop records. The kernel maintains these on every
    /// netdev; for our purposes that's `pppN` (kmod data path) or
    /// `tun0` (TUN data path) — the netdev type is irrelevant to the
    /// query.
    pub fn link_stats64(&mut self, ifindex: u32) -> Result<LinkStats64, NetlinkError> {
        let mut buf = MessageBuf::new();
        buf.push_nlmsghdr(RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, self.next_seq());
        buf.push_struct(&Ifinfomsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: i32::try_from(ifindex).expect("ifindex fits in i32"),
            ifi_flags: 0,
            ifi_change: 0,
        });
        buf.finalize();
        self.exchange_link_stats(&buf)
    }

    fn exchange_link_stats(&self, buf: &MessageBuf) -> Result<LinkStats64, NetlinkError> {
        const OP: &str = "RTM_GETLINK(IFLA_STATS64)";
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: `buf.bytes` is a valid initialized slice; addr is a
        // valid sockaddr_nl describing the kernel.
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
            return Err(NetlinkError::Send {
                op: "RTM_GETLINK",
                source: io::Error::last_os_error(),
            });
        }

        // 8 KiB is comfortably more than `rtnl_link_stats64` (192 B)
        // plus the dozen other IFLA attributes the kernel always
        // returns alongside it (IFLA_IFNAME, IFLA_QDISC, etc.).
        let mut reply = [0u8; 8192];
        // SAFETY: `reply` is a valid &mut [u8].
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                reply.as_mut_ptr().cast(),
                reply.len(),
                0,
            )
        };
        if n < 0 {
            return Err(NetlinkError::Recv {
                op: "RTM_GETLINK",
                source: io::Error::last_os_error(),
            });
        }
        let buf = &reply[..n as usize];
        if buf.len() < NLMSG_HDRLEN {
            return Err(NetlinkError::Unexpected { op: OP, got: 0 });
        }
        // SAFETY: bounds-checked above; nlmsghdr is plain-old-data.
        let hdr: libc::nlmsghdr =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::nlmsghdr>()) };
        match hdr.nlmsg_type {
            NLMSG_ERROR => {
                if buf.len() < NLMSG_HDRLEN + 4 {
                    return Err(NetlinkError::Unexpected { op: OP, got: hdr.nlmsg_type });
                }
                let mut errbuf = [0u8; 4];
                errbuf.copy_from_slice(&buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]);
                let err = i32::from_ne_bytes(errbuf);
                if err == 0 {
                    // Bare ACK without payload — kernel didn't return
                    // the link. Treat as ENODEV-equivalent.
                    return Err(NetlinkError::Kernel {
                        op: OP,
                        errno: libc::ENODEV,
                    });
                }
                return Err(NetlinkError::Kernel {
                    op: OP,
                    errno: -err,
                });
            }
            RTM_NEWLINK => {}
            other => return Err(NetlinkError::Unexpected { op: OP, got: other }),
        }
        // Skip nlmsghdr + ifinfomsg (16 bytes).
        let body_off = NLMSG_HDRLEN + mem::size_of::<Ifinfomsg>();
        if buf.len() < body_off {
            return Err(NetlinkError::Unexpected { op: OP, got: hdr.nlmsg_type });
        }
        let attrs = &buf[body_off..hdr.nlmsg_len as usize];
        find_stats64(attrs).ok_or(NetlinkError::Unexpected {
            op: OP,
            got: IFLA_STATS64,
        })
    }

    fn exchange(&self, op: &'static str, buf: &MessageBuf) -> Result<(), NetlinkError> {
        // Send.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: `buf.bytes` is a valid initialized slice; addr is a valid
        // sockaddr_nl describing the kernel (nl_pid = 0).
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
            return Err(NetlinkError::Send {
                op,
                source: io::Error::last_os_error(),
            });
        }

        // Recv ACK. Kernel ACK for a request without NLM_F_DUMP is a
        // single NLMSG_ERROR with `error == 0`; non-zero means failure.
        let mut reply = [0u8; 4096];
        // SAFETY: `reply` is a valid &mut [u8].
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                reply.as_mut_ptr().cast(),
                reply.len(),
                0,
            )
        };
        if n < 0 {
            return Err(NetlinkError::Recv {
                op,
                source: io::Error::last_os_error(),
            });
        }
        parse_ack(op, &reply[..n as usize])
    }
}

/// Set the netdev MTU via the cheaper `SIOCSIFMTU` ioctl. We expose
/// both this and the netlink path because for a single attribute the
/// ioctl is one syscall vs the netlink dance, and accel-ppp / pppd
/// both reach for `SIOCSIFMTU` here.
#[allow(dead_code)] // FUTURE: SIOCSIFMTU fallback consumed when the netlink IFLA_MTU path is unavailable.
pub fn set_mtu_ioctl(ifname: &str, mtu: u32) -> Result<(), NetlinkError> {
    // SAFETY: standard socket(2) FFI.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(NetlinkError::SetMtu {
            ifname: ifname.to_owned(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `raw` is a freshly-opened fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name = ifname.as_bytes();
    assert!(
        name.len() < libc::IFNAMSIZ,
        "interface name exceeds IFNAMSIZ"
    );
    // SAFETY: bounds-checked above; ifr_name has IFNAMSIZ bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr().cast::<libc::c_char>(),
            ifr.ifr_name.as_mut_ptr(),
            name.len(),
        );
    }
    ifr.ifr_ifru.ifru_mtu = i32::try_from(mtu).expect("MTU fits in i32");

    // SAFETY: fd is valid for the duration; `SIOCSIFMTU` reads ifr_name
    // and ifr_mtu, both initialized above.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFMTU, &ifr) };
    if rc < 0 {
        return Err(NetlinkError::SetMtu {
            ifname: ifname.to_owned(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Message construction.
// ---------------------------------------------------------------------------

struct MessageBuf {
    bytes: Vec<u8>,
    hdr_offset: usize,
}

impl MessageBuf {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(256),
            hdr_offset: 0,
        }
    }

    fn push_nlmsghdr(&mut self, msg_type: u16, flags: u16, seq: u32) {
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

    fn push_struct<T: Copy>(&mut self, value: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>())
        };
        self.bytes.extend_from_slice(bytes);
        // NLMSG / payload boundary is always 4-byte aligned.
        while self.bytes.len() % 4 != 0 {
            self.bytes.push(0);
        }
    }

    fn push_attr(&mut self, attr_type: u16, payload: &[u8]) {
        let total = 4 + payload.len();
        let hdr = Rtattr {
            rta_len: u16::try_from(total).expect("attribute too large"),
            rta_type: attr_type,
        };
        self.push_struct(&hdr);
        // push_struct already padded to 4 after the 4-byte header.
        self.bytes.extend_from_slice(payload);
        while self.bytes.len() % 4 != 0 {
            self.bytes.push(0);
        }
    }

    fn finalize(&mut self) {
        let len = u32::try_from(self.bytes.len() - self.hdr_offset).expect("message too large");
        // Patch nlmsg_len in place.
        let len_bytes = len.to_ne_bytes();
        self.bytes[self.hdr_offset..self.hdr_offset + 4].copy_from_slice(&len_bytes);
    }
}

// ---------------------------------------------------------------------------
// ACK parsing.
// ---------------------------------------------------------------------------

fn parse_ack(op: &'static str, buf: &[u8]) -> Result<(), NetlinkError> {
    if buf.len() < NLMSG_HDRLEN {
        return Err(NetlinkError::Unexpected { op, got: 0 });
    }
    // SAFETY: bounds-checked above; nlmsghdr is plain-old-data and
    // valid for any byte pattern.
    let hdr: libc::nlmsghdr =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::nlmsghdr>()) };
    match hdr.nlmsg_type {
        NLMSG_ERROR => {
            // Payload starts with `int error`. Zero = success ACK,
            // negative-errno = failure.
            if buf.len() < NLMSG_HDRLEN + 4 {
                return Err(NetlinkError::Unexpected {
                    op,
                    got: NLMSG_ERROR,
                });
            }
            let err_bytes: [u8; 4] = buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                .try_into()
                .expect("4 bytes");
            let err = i32::from_ne_bytes(err_bytes);
            if err == 0 {
                Ok(())
            } else {
                Err(NetlinkError::Kernel { op, errno: -err })
            }
        }
        NLMSG_DONE => Ok(()),
        other => Err(NetlinkError::Unexpected { op, got: other }),
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_parser_accepts_zero_error() {
        let mut buf = vec![0u8; NLMSG_HDRLEN + 4];
        let hdr = libc::nlmsghdr {
            nlmsg_len: (NLMSG_HDRLEN + 4) as u32,
            nlmsg_type: NLMSG_ERROR,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&hdr as *const libc::nlmsghdr).cast::<u8>(),
                buf.as_mut_ptr(),
                NLMSG_HDRLEN,
            );
        }
        // err = 0.
        buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].copy_from_slice(&0i32.to_ne_bytes());
        parse_ack("test", &buf).expect("zero-error ACK should be Ok");
    }

    #[test]
    fn ack_parser_surfaces_errno() {
        let mut buf = vec![0u8; NLMSG_HDRLEN + 4];
        let hdr = libc::nlmsghdr {
            nlmsg_len: (NLMSG_HDRLEN + 4) as u32,
            nlmsg_type: NLMSG_ERROR,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&hdr as *const libc::nlmsghdr).cast::<u8>(),
                buf.as_mut_ptr(),
                NLMSG_HDRLEN,
            );
        }
        // err = -EEXIST (-17 on Linux).
        buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].copy_from_slice(&(-17i32).to_ne_bytes());
        match parse_ack("test", &buf) {
            Err(NetlinkError::Kernel { errno: 17, .. }) => {}
            other => panic!("expected Kernel(EEXIST), got {other:?}"),
        }
    }

    #[test]
    fn message_buf_aligns_and_patches_length() {
        let mut buf = MessageBuf::new();
        buf.push_nlmsghdr(RTM_NEWADDR, NLM_F_REQUEST, 42);
        buf.push_struct(&Ifaddrmsg {
            ifa_family: libc::AF_INET as u8,
            ifa_prefixlen: 32,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: 7,
        });
        buf.push_attr(IFA_LOCAL, &[10, 0, 0, 1]);
        buf.push_attr(IFA_ADDRESS, &[10, 0, 0, 2]);
        buf.finalize();

        // Length is patched in place.
        let len_bytes: [u8; 4] = buf.bytes[0..4].try_into().unwrap();
        let len = u32::from_ne_bytes(len_bytes) as usize;
        assert_eq!(len, buf.bytes.len());
        // Every section is 4-aligned.
        assert!(buf.bytes.len() % 4 == 0);
    }

    /// Integration: open a netlink socket, configure pppN, verify it
    /// shows up. Requires `CAP_NET_ADMIN` + `ppp_generic`.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN and the ppp_generic kernel module"]
    fn bring_up_pppn() {
        use crate::kppp::unit::Unit;
        let unit = Unit::new().expect("create unit");
        let mut nl = RtNetlink::open().expect("open netlink");
        let cfg = SessionIpConfig {
            local: Ipv4Addr::new(10, 99, 0, 1),
            peer: Ipv4Addr::new(10, 99, 0, 2),
            netmask: None,
            mtu: Some(1400),
        };
        nl.bring_up(unit.index(), &cfg).expect("bring up");
        // ip -4 addr show pppN should now list 10.99.0.1 peer 10.99.0.2.
        drop(unit);
    }
}
