//! `NETLINK_ROUTE` operations for `pppN` / `tun` bring-up.
//!
//! Sister of [`crate::shape::netlink`], scoped to the message types
//! we need at session bring-up time:
//!
//! - `RTM_NEWADDR` to install the P2P IPv4 address pair (local +
//!   peer) on the unit.
//! - `RTM_NEWLINK` to bring the link UP and set the MTU.
//! - `RTM_GETLINK` (with no `NLM_F_DUMP`) to read the kernel's
//!   `IFLA_STATS64` counters for RADIUS Interim-Update / Stop.
//! - `RTM_NEWROUTE` to install RADIUS `Framed-Route` entries
//!   against the unit's ifindex.
//!
//! The wire-format builder, socket wrapper, and ACK draining loop
//! live in [`crate::netlink`]; this module is the rtnetlink-flavoured
//! façade over them. Queues, qdiscs and neighbour table are out of
//! scope and live next door in [`crate::shape`].

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::struct_field_names
)]

use std::collections::HashSet;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::netlink::{
    self, DrainError, MessageBuf, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE,
    NLM_F_REQUEST, NLMSG_HDRLEN, NetlinkSocket,
};

use super::SessionIpConfig;

// ---------------------------------------------------------------------------
// rtnetlink message numbers / attribute IDs that aren't in libc.
// ---------------------------------------------------------------------------

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const IFLA_MTU: u16 = 4;
/// `IFLA_STATS64` — kernel-maintained per-netdev byte/packet counters
/// (`struct rtnl_link_stats64` from `<linux/if_link.h>`). 192 bytes,
/// 24 × `u64` host-byte-order.
const IFLA_STATS64: u16 = 23;

// `<linux/rtnetlink.h>` — `RTA_*` attribute types for `struct rtmsg`.
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;

// `rtm_protocol` values.
const RTPROT_BOOT: u8 = 3;
// `rtm_scope` values.
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
// `rtm_type` values.
const RTN_UNICAST: u8 = 1;
// `rtm_table` values.
const RT_TABLE_MAIN: u8 = 254;

// ---------------------------------------------------------------------------
// Family-specific message structs (`<linux/if_addr.h>`,
// `<linux/if_link.h>`).
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
struct Rtmsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
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
        let aligned = netlink::nlmsg_align(rta_len);
        if aligned >= attrs.len() {
            return None;
        }
        attrs = &attrs[aligned..];
    }
    None
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    #[error("opening NETLINK_ROUTE socket: {0}")]
    Socket(#[source] io::Error),
    #[error("binding NETLINK_ROUTE socket: {0}")]
    #[allow(dead_code)]
    // Kept for API stability; the shared NetlinkSocket::open collapses socket+bind into a single io::Error.
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
    #[allow(dead_code)] // FUTURE: paired with `set_mtu_ioctl` fallback below.
    SetMtu {
        ifname: String,
        #[source]
        source: io::Error,
    },
}

// ---------------------------------------------------------------------------
// rtnetlink client.
// ---------------------------------------------------------------------------

/// A `NETLINK_ROUTE` socket scoped to `pppN` / `tun` bring-up.
/// Synchronous; one-request-one-ACK at a time.
#[derive(Debug)]
pub struct RtNetlink {
    sock: NetlinkSocket,
    seq: u32,
}

impl RtNetlink {
    pub fn open() -> Result<Self, NetlinkError> {
        let sock = NetlinkSocket::open(libc::NETLINK_ROUTE).map_err(NetlinkError::Socket)?;
        Ok(Self { sock, seq: 1 })
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Configure a `pppN` unit with the P2P address pair from IPCP and
    /// bring it administratively up.
    pub fn bring_up(&mut self, ifindex: u32, cfg: &SessionIpConfig) -> Result<(), NetlinkError> {
        tracing::trace!(
            target: "sstp::mtu",
            ifindex,
            mtu = ?cfg.mtu,
            local = %cfg.local,
            peer = %cfg.peer,
            "RtNetlink::bring_up: programming netdev (MTU + P2P addr + IFF_UP)"
        );
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
        let buf = encode_add_p2p_addr(self.next_seq(), ifindex, local, peer);
        self.exchange("RTM_NEWADDR", &buf)
    }

    /// `RTM_NEWLINK` with `IFF_UP` set in `ifi_flags` and the same bit
    /// in `ifi_change` (so the kernel only touches that flag).
    pub fn set_link_up(&mut self, ifindex: u32) -> Result<(), NetlinkError> {
        let buf = encode_set_link_up(self.next_seq(), ifindex);
        self.exchange("RTM_NEWLINK(IFF_UP)", &buf)
    }

    /// `RTM_NEWLINK` carrying an `IFLA_MTU` attribute.
    pub fn set_mtu(&mut self, ifindex: u32, mtu: u32) -> Result<(), NetlinkError> {
        tracing::trace!(
            target: "sstp::mtu",
            ifindex,
            mtu,
            "RTM_NEWLINK(IFLA_MTU): writing IFLA_MTU"
        );
        let buf = encode_set_mtu(self.next_seq(), ifindex, mtu);
        self.exchange("RTM_NEWLINK(IFLA_MTU)", &buf)
    }

    /// `RTM_NEWROUTE` installing an IPv4 unicast route through the
    /// given `pppN` `ifindex`. Used to apply each `Framed-Route`
    /// (RFC 2865 §5.22) returned in an Access-Accept.
    ///
    /// `prefix` is the destination prefix length (0..=32). When
    /// `gateway` is `None` the route is installed as
    /// `RT_SCOPE_LINK` (the kernel resolves the next-hop on the P2P
    /// netdev itself); otherwise `RT_SCOPE_UNIVERSE` plus an
    /// `RTA_GATEWAY`.
    ///
    /// Routes installed against `pppN` are auto-removed by the
    /// kernel when the netdev disappears, so there is no explicit
    /// teardown path.
    pub fn add_route(
        &mut self,
        ifindex: u32,
        dest: Ipv4Addr,
        prefix: u8,
        gateway: Option<Ipv4Addr>,
        metric: Option<u32>,
    ) -> Result<(), NetlinkError> {
        let buf = encode_add_route(self.next_seq(), ifindex, dest, prefix, gateway, metric);
        self.exchange("RTM_NEWROUTE", &buf)
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
        const OP: &str = "RTM_GETLINK(IFLA_STATS64)";
        let seq = self.next_seq();
        let mut buf = MessageBuf::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
        buf.push_struct(&Ifinfomsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: i32::try_from(ifindex).expect("ifindex fits in i32"),
            ifi_flags: 0,
            ifi_change: 0,
        });
        buf.finalize();

        self.sock
            .send(buf.bytes())
            .map_err(|source| NetlinkError::Send {
                op: "RTM_GETLINK",
                source,
            })?;

        // 8 KiB is comfortably more than `rtnl_link_stats64` (192 B)
        // plus the dozen other IFLA attributes the kernel always
        // returns alongside it (IFLA_IFNAME, IFLA_QDISC, etc.).
        let mut reply = [0u8; 8192];
        let received = self
            .sock
            .recv_into(&mut reply)
            .map_err(|source| NetlinkError::Recv {
                op: "RTM_GETLINK",
                source,
            })?;

        if received.len() < NLMSG_HDRLEN {
            return Err(NetlinkError::Unexpected { op: OP, got: 0 });
        }
        // SAFETY: bounds-checked above; nlmsghdr is plain-old-data.
        let hdr: libc::nlmsghdr =
            unsafe { std::ptr::read_unaligned(received.as_ptr().cast::<libc::nlmsghdr>()) };
        match hdr.nlmsg_type {
            netlink::NLMSG_ERROR => {
                if received.len() < NLMSG_HDRLEN + 4 {
                    return Err(NetlinkError::Unexpected {
                        op: OP,
                        got: hdr.nlmsg_type,
                    });
                }
                let mut errbuf = [0u8; 4];
                errbuf.copy_from_slice(&received[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]);
                let err = i32::from_ne_bytes(errbuf);
                if err == 0 {
                    // Bare ACK without payload — kernel didn't return
                    // the link. Treat as ENODEV-equivalent.
                    Err(NetlinkError::Kernel {
                        op: OP,
                        errno: libc::ENODEV,
                    })
                } else {
                    Err(NetlinkError::Kernel {
                        op: OP,
                        errno: -err,
                    })
                }
            }
            RTM_NEWLINK => {
                let body_off = NLMSG_HDRLEN + mem::size_of::<Ifinfomsg>();
                if received.len() < body_off {
                    return Err(NetlinkError::Unexpected {
                        op: OP,
                        got: hdr.nlmsg_type,
                    });
                }
                let attrs = &received[body_off..hdr.nlmsg_len as usize];
                find_stats64(attrs).ok_or(NetlinkError::Unexpected {
                    op: OP,
                    got: IFLA_STATS64,
                })
            }
            other => Err(NetlinkError::Unexpected { op: OP, got: other }),
        }
    }

    /// Send a fully-built request and consume its single
    /// `NLMSG_ERROR` ack.
    fn exchange(&mut self, op: &'static str, buf: &MessageBuf) -> Result<(), NetlinkError> {
        self.sock
            .send(buf.bytes())
            .map_err(|source| NetlinkError::Send { op, source })?;

        let mut reply = [0u8; 4096];
        let received = self
            .sock
            .recv_into(&mut reply)
            .map_err(|source| NetlinkError::Recv { op, source })?;

        let mut remaining: HashSet<u32> = [buf.seq()].into_iter().collect();
        match netlink::drain_acks(received, &mut remaining) {
            Ok(()) if remaining.is_empty() => Ok(()),
            Ok(()) => Err(NetlinkError::Unexpected { op, got: 0 }),
            Err(DrainError::Truncated) => Err(NetlinkError::Recv {
                op,
                source: io::Error::other("truncated netlink ack"),
            }),
            Err(DrainError::Kernel(errno)) => Err(NetlinkError::Kernel { op, errno }),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure encoders.
//
// Extracted so the wire format can be unit-tested without opening
// a `NETLINK_ROUTE` socket. Every public method on `RtNetlink`
// builds its message via one of these and then hands the buffer
// to `exchange()`.
// ---------------------------------------------------------------------------

fn encode_add_p2p_addr(seq: u32, ifindex: u32, local: Ipv4Addr, peer: Ipv4Addr) -> MessageBuf {
    let mut buf = MessageBuf::new(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL,
        seq,
    );
    buf.push_struct(&Ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: 32,
        ifa_flags: 0,
        ifa_scope: 0, // RT_SCOPE_UNIVERSE
        ifa_index: ifindex,
    });
    buf.push_attr_bytes(IFA_LOCAL, &local.octets());
    buf.push_attr_bytes(IFA_ADDRESS, &peer.octets());
    buf.finalize();
    buf
}

fn encode_set_link_up(seq: u32, ifindex: u32) -> MessageBuf {
    let mut buf = MessageBuf::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    buf.push_struct(&Ifinfomsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: i32::try_from(ifindex).expect("ifindex fits in i32"),
        ifi_flags: libc::IFF_UP as u32,
        ifi_change: libc::IFF_UP as u32,
    });
    buf.finalize();
    buf
}

fn encode_set_mtu(seq: u32, ifindex: u32, mtu: u32) -> MessageBuf {
    let mut buf = MessageBuf::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    buf.push_struct(&Ifinfomsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: i32::try_from(ifindex).expect("ifindex fits in i32"),
        ifi_flags: 0,
        ifi_change: 0,
    });
    buf.push_attr_bytes(IFLA_MTU, &mtu.to_ne_bytes());
    buf.finalize();
    buf
}

fn encode_add_route(
    seq: u32,
    ifindex: u32,
    dest: Ipv4Addr,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    metric: Option<u32>,
) -> MessageBuf {
    let mut buf = MessageBuf::new(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    let scope = if gateway.is_some() {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    buf.push_struct(&Rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: prefix,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_BOOT,
        rtm_scope: scope,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    });
    buf.push_attr_bytes(RTA_DST, &dest.octets());
    buf.push_attr_bytes(RTA_OIF, &ifindex.to_ne_bytes());
    if let Some(gw) = gateway {
        buf.push_attr_bytes(RTA_GATEWAY, &gw.octets());
    }
    if let Some(m) = metric {
        buf.push_attr_bytes(RTA_PRIORITY, &m.to_ne_bytes());
    }
    buf.finalize();
    buf
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
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Helpers shared by the encoder tests.
    // -----------------------------------------------------------------

    /// nlmsghdr layout: u32 len, u16 type, u16 flags, u32 seq, u32 pid.
    fn read_nlmsghdr(bytes: &[u8]) -> (u32, u16, u16, u32) {
        assert!(bytes.len() >= NLMSG_HDRLEN, "buffer shorter than nlmsghdr");
        let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let typ = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        (len, typ, flags, seq)
    }

    /// Walk the `rtattr` stream that follows the message-specific
    /// fixed header and return `(type, payload)` tuples.
    fn parse_attrs(mut attrs: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        while attrs.len() >= 4 {
            let nla_len = u16::from_ne_bytes(attrs[0..2].try_into().unwrap()) as usize;
            let nla_type = u16::from_ne_bytes(attrs[2..4].try_into().unwrap());
            assert!(nla_len >= 4 && nla_len <= attrs.len(), "bogus nla_len");
            out.push((nla_type, attrs[4..nla_len].to_vec()));
            let aligned = netlink::nlmsg_align(nla_len);
            if aligned >= attrs.len() {
                break;
            }
            attrs = &attrs[aligned..];
        }
        out
    }

    fn find_attr(attrs: &[(u16, Vec<u8>)], typ: u16) -> &[u8] {
        attrs.iter().find(|(t, _)| *t == typ).map_or_else(
            || panic!("attribute type {typ} not found"),
            |(_, p)| p.as_slice(),
        )
    }

    // -----------------------------------------------------------------
    // Pure parsers.
    // -----------------------------------------------------------------

    fn build_stats64_payload(rxp: u64, txp: u64, rxb: u64, txb: u64) -> [u8; 192] {
        // 24 × u64 = 192 bytes; we only populate the first four
        // counters to mirror what `LinkStats64::from_payload` reads.
        let mut buf = [0u8; 192];
        buf[0..8].copy_from_slice(&rxp.to_ne_bytes());
        buf[8..16].copy_from_slice(&txp.to_ne_bytes());
        buf[16..24].copy_from_slice(&rxb.to_ne_bytes());
        buf[24..32].copy_from_slice(&txb.to_ne_bytes());
        buf
    }

    #[test]
    fn link_stats64_parses_first_four_counters() {
        let raw = build_stats64_payload(1, 2, 3, 4);
        let s = LinkStats64::from_payload(&raw).expect("parse");
        assert_eq!(s.rx_packets, 1);
        assert_eq!(s.tx_packets, 2);
        assert_eq!(s.rx_bytes, 3);
        assert_eq!(s.tx_bytes, 4);
    }

    #[test]
    fn link_stats64_rejects_short_payload() {
        let short = [0u8; 31];
        assert!(LinkStats64::from_payload(&short).is_none());
    }

    #[test]
    fn link_stats64_accepts_exactly_32_bytes() {
        let mut raw = [0u8; 32];
        raw[24..32].copy_from_slice(&u64::MAX.to_ne_bytes());
        let s = LinkStats64::from_payload(&raw).expect("parse");
        assert_eq!(s.tx_bytes, u64::MAX);
    }

    /// Build a `[type:u16][len:u16]`-prefixed rtattr stream with
    /// 4-byte alignment between attributes.
    fn build_attrs(items: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (typ, payload) in items {
            let total = 4 + payload.len();
            out.extend_from_slice(&(total as u16).to_ne_bytes());
            out.extend_from_slice(&typ.to_ne_bytes());
            out.extend_from_slice(payload);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        out
    }

    #[test]
    fn find_stats64_returns_none_when_absent() {
        let attrs = build_attrs(&[(IFLA_MTU, &1500u32.to_ne_bytes())]);
        assert!(find_stats64(&attrs).is_none());
    }

    #[test]
    fn find_stats64_returns_none_for_empty() {
        assert!(find_stats64(&[]).is_none());
    }

    #[test]
    fn find_stats64_skips_unrelated_attrs_and_returns_payload() {
        let stats = build_stats64_payload(10, 20, 30, 40);
        let attrs = build_attrs(&[
            (IFLA_MTU, &1500u32.to_ne_bytes()),
            (IFLA_STATS64, &stats[..]),
            (IFLA_MTU, &9000u32.to_ne_bytes()),
        ]);
        let s = find_stats64(&attrs).expect("present");
        assert_eq!(s.rx_packets, 10);
        assert_eq!(s.tx_bytes, 40);
    }

    #[test]
    fn find_stats64_rejects_truncated_attribute() {
        // Declare nla_len = 200 but only provide 8 bytes after the
        // header → walker must bail out instead of indexing past.
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&200u16.to_ne_bytes()); // nla_len
        attrs.extend_from_slice(&IFLA_STATS64.to_ne_bytes()); // nla_type
        attrs.extend_from_slice(&[0u8; 8]);
        assert!(find_stats64(&attrs).is_none());
    }

    #[test]
    fn find_stats64_rejects_bogus_short_len() {
        // nla_len < 4 → invalid; walker must return None.
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&2u16.to_ne_bytes());
        attrs.extend_from_slice(&IFLA_STATS64.to_ne_bytes());
        assert!(find_stats64(&attrs).is_none());
    }

    // -----------------------------------------------------------------
    // Encoder wire-format tests.
    // -----------------------------------------------------------------

    #[test]
    fn encode_add_p2p_addr_layout() {
        let buf = encode_add_p2p_addr(
            42,
            7,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let bytes = buf.bytes();

        let (msg_len, msg_type, flags, seq) = read_nlmsghdr(bytes);
        assert_eq!(msg_len as usize, bytes.len(), "nlmsg_len matches payload");
        assert_eq!(msg_type, RTM_NEWADDR);
        assert_eq!(seq, 42);
        assert_eq!(
            flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL
        );

        // Ifaddrmsg starts at NLMSG_HDRLEN.
        let body = &bytes[NLMSG_HDRLEN..];
        assert_eq!(body[0], libc::AF_INET as u8); // ifa_family
        assert_eq!(body[1], 32); // ifa_prefixlen (host route on P2P)
        assert_eq!(body[2], 0); // ifa_flags
        assert_eq!(body[3], 0); // ifa_scope = RT_SCOPE_UNIVERSE
        let ifa_index = u32::from_ne_bytes(body[4..8].try_into().unwrap());
        assert_eq!(ifa_index, 7);

        let attrs = parse_attrs(&body[mem::size_of::<Ifaddrmsg>()..]);
        assert_eq!(find_attr(&attrs, IFA_LOCAL), &[10, 0, 0, 1]);
        assert_eq!(find_attr(&attrs, IFA_ADDRESS), &[10, 0, 0, 2]);
    }

    #[test]
    fn encode_set_link_up_only_touches_iff_up() {
        let buf = encode_set_link_up(99, 12);
        let bytes = buf.bytes();

        let (_, msg_type, flags, seq) = read_nlmsghdr(bytes);
        assert_eq!(msg_type, RTM_NEWLINK);
        assert_eq!(seq, 99);
        assert_eq!(flags, NLM_F_REQUEST | NLM_F_ACK);

        let body = &bytes[NLMSG_HDRLEN..];
        assert_eq!(body[0], libc::AF_UNSPEC as u8);
        let ifi_index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
        assert_eq!(ifi_index, 12);
        let ifi_flags = u32::from_ne_bytes(body[8..12].try_into().unwrap());
        let ifi_change = u32::from_ne_bytes(body[12..16].try_into().unwrap());
        assert_eq!(ifi_flags, libc::IFF_UP as u32);
        assert_eq!(
            ifi_change, ifi_flags,
            "ifi_change must equal ifi_flags so kernel touches only IFF_UP"
        );
        // No attributes after the fixed header.
        assert_eq!(bytes.len(), NLMSG_HDRLEN + mem::size_of::<Ifinfomsg>());
    }

    #[test]
    fn encode_set_mtu_emits_ifla_mtu_attr() {
        let buf = encode_set_mtu(1, 9, 1400);
        let bytes = buf.bytes();
        let (_, msg_type, _, _) = read_nlmsghdr(bytes);
        assert_eq!(msg_type, RTM_NEWLINK);
        let body = &bytes[NLMSG_HDRLEN..];
        let attrs = parse_attrs(&body[mem::size_of::<Ifinfomsg>()..]);
        let mtu_payload = find_attr(&attrs, IFLA_MTU);
        let mtu = u32::from_ne_bytes(mtu_payload.try_into().unwrap());
        assert_eq!(mtu, 1400);

        // ifi_change must be 0 for the MTU-only path so the kernel
        // doesn't reset other link flags.
        let ifi_change = u32::from_ne_bytes(body[12..16].try_into().unwrap());
        assert_eq!(ifi_change, 0);
    }

    #[test]
    fn encode_add_route_with_gateway_uses_universe_scope() {
        let buf = encode_add_route(
            5,
            10,
            Ipv4Addr::new(192, 0, 2, 0),
            24,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            Some(100),
        );
        let bytes = buf.bytes();

        let (_, msg_type, flags, _) = read_nlmsghdr(bytes);
        assert_eq!(msg_type, RTM_NEWROUTE);
        assert_eq!(
            flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        );

        let body = &bytes[NLMSG_HDRLEN..];
        assert_eq!(body[0], libc::AF_INET as u8); // rtm_family
        assert_eq!(body[1], 24); // rtm_dst_len
        assert_eq!(body[4], RT_TABLE_MAIN);
        assert_eq!(body[5], RTPROT_BOOT);
        assert_eq!(body[6], RT_SCOPE_UNIVERSE);
        assert_eq!(body[7], RTN_UNICAST);

        let attrs = parse_attrs(&body[mem::size_of::<Rtmsg>()..]);
        assert_eq!(find_attr(&attrs, RTA_DST), &[192, 0, 2, 0]);
        let oif = u32::from_ne_bytes(find_attr(&attrs, RTA_OIF).try_into().unwrap());
        assert_eq!(oif, 10);
        assert_eq!(find_attr(&attrs, RTA_GATEWAY), &[10, 0, 0, 2]);
        let prio = u32::from_ne_bytes(find_attr(&attrs, RTA_PRIORITY).try_into().unwrap());
        assert_eq!(prio, 100);
    }

    #[test]
    fn encode_add_route_without_gateway_uses_link_scope() {
        let buf = encode_add_route(1, 4, Ipv4Addr::new(198, 51, 100, 0), 24, None, None);
        let bytes = buf.bytes();
        let body = &bytes[NLMSG_HDRLEN..];
        assert_eq!(body[6], RT_SCOPE_LINK);

        let attrs = parse_attrs(&body[mem::size_of::<Rtmsg>()..]);
        // Neither RTA_GATEWAY nor RTA_PRIORITY should be present.
        assert!(attrs.iter().all(|(t, _)| *t != RTA_GATEWAY));
        assert!(attrs.iter().all(|(t, _)| *t != RTA_PRIORITY));
        assert_eq!(find_attr(&attrs, RTA_DST), &[198, 51, 100, 0]);
    }

    #[test]
    fn encode_add_route_zero_prefix_default_gateway() {
        let buf = encode_add_route(
            1,
            4,
            Ipv4Addr::UNSPECIFIED,
            0,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            None,
        );
        let bytes = buf.bytes();
        let body = &bytes[NLMSG_HDRLEN..];
        assert_eq!(body[1], 0); // rtm_dst_len = 0 → default route
        assert_eq!(body[6], RT_SCOPE_UNIVERSE);
    }

    // -----------------------------------------------------------------
    // Integration: real netlink socket, kernel-side reflection.
    // -----------------------------------------------------------------

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
