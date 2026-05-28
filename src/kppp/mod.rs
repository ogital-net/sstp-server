//! Kernel PPP data-plane bindings (`/dev/ppp`, `pppN` netdev lifecycle).
//!
//! Once IPCP converges in the in-process [`crate::ppp`] state machine,
//! the session is handed to the kernel: we open `/dev/ppp`, create a
//! new PPP unit (`PPPIOCNEWUNIT`), and bind the resulting `pppN`
//! interface into the host's normal IP forwarding path. From then on
//! the kernel owns IP routing for that session.
//!
//! ## What this module is *not*
//!
//! Mainline Linux's PPP generic driver supports two fd flavours on
//! `/dev/ppp`: **unit fds** (associated with a `pppN` netdev) and
//! **channel fds** (associated with an underlying transport). Channels
//! are registered by in-kernel transport drivers — `pppoe`, `pppol2tp`,
//! `pptp`, `ppp_async`. There is **no generic userspace-channel
//! interface** for arbitrary tunnels like SSTP, so we cannot push the
//! per-packet data path into the kernel the way `pppoe` does without
//! shipping a custom kernel module.
//!
//! The model we use is the same one `pppd` uses over a pty: open
//! `/dev/ppp`, `PPPIOCNEWUNIT` to create the unit, then treat the unit
//! fd as a bidirectional pipe of PPP-encapsulated frames. IP packets
//! the kernel wants to send out are `read(2)` from the unit fd and
//! pushed back through the SSTP/TLS socket in userspace; SSTP data
//! frames received from the client are `write(2)`-en into the unit fd.
//! Per-packet userspace involvement is the unavoidable consequence of
//! terminating TLS in process.
//!
//! ## Module layout
//!
//! - [`ioctl`] — `/dev/ppp` ioctl numbers and the minimum-surface
//!   `unsafe` wrappers around `libc::ioctl`. Every `unsafe` block
//!   carries a `// SAFETY:` comment naming the invariant.
//! - [`unit`] — [`Unit`] owns a unit fd and the kernel-assigned
//!   `pppN` index.
//!
//! ## Status
//!
//! M5 scaffolding only: ioctl numbers + `Unit::new` + MRU/flags
//! setters. The async read/write half (tokio `AsyncFd` integration)
//! and netlink-driven address/route push land with M6 when sessions
//! actually need them.

#![allow(dead_code)]

pub mod ioctl;
pub mod netlink;
pub mod unit;

/// IPv4 configuration applied to a `pppN` interface after IPCP.
///
/// Populated from [`crate::auth::AuthAccept`] by M6; consumed by the
/// netlink bring-up step in this module. Lives here (not in `auth`)
/// because the type is what kppp accepts as input — `auth` may grow
/// fields kppp doesn't care about.
#[derive(Debug, Clone)]
pub struct SessionIpConfig {
    pub local: std::net::Ipv4Addr,
    pub peer: std::net::Ipv4Addr,
    pub netmask: Option<std::net::Ipv4Addr>,
    pub mtu: Option<u32>,
}
