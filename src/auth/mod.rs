//! PPP ↔ RADIUS bridge.
//!
//! The PPP authentication phase (PAP / CHAP / MS-CHAPv2 / EAP) is
//! terminated to a RADIUS authenticator (us) rather than verified
//! locally. We translate the inbound PPP-auth packet to an
//! Access-Request, drive the RADIUS round-trip, and project the
//! reply into the [`AuthResult`] our session bring-up consumes.
//!
//! sstp-server is the *client* of RADIUS in this picture; the
//! `radius-tokio` crate it builds on is a server library, so most of
//! this module is wiring its low-level codec into a UDP request
//! originator with `(peer, identifier)` correlation and RFC 5080
//! retry semantics.

#![allow(dead_code)]

pub mod accounting;
pub mod bridge;
pub mod client;
pub mod coa;
pub mod request;
pub mod reply;

use std::net::{Ipv4Addr, SocketAddr};

/// Result of a successful RADIUS authentication.
///
/// Populated from the Access-Accept; consumed by the session
/// bring-up path to bind a kernel PPP unit, advertise IPCP options
/// to the peer, and seed the SSTP Crypto Binding HLAK.
#[derive(Debug, Clone)]
pub struct AuthAccept {
    /// `Framed-IP-Address` (RFC 2865 §5.8) — required.
    pub framed_ip: Ipv4Addr,
    /// `Framed-IP-Netmask` (RFC 2865 §5.9).
    pub framed_netmask: Option<Ipv4Addr>,
    /// `Framed-MTU` (RFC 2865 §5.12).
    pub framed_mtu: Option<u32>,
    /// `MS-Primary-DNS-Server` (RFC 2548 §2.1.4).
    pub primary_dns: Option<Ipv4Addr>,
    /// `MS-Secondary-DNS-Server`.
    pub secondary_dns: Option<Ipv4Addr>,
    /// `MS-Primary-NBNS-Server`.
    pub primary_nbns: Option<Ipv4Addr>,
    /// `MS-Secondary-NBNS-Server`.
    pub secondary_nbns: Option<Ipv4Addr>,
    /// MPPE Send key (RFC 3079) — server-to-peer. Empty for PAP /
    /// CHAP without MPPE; populated for MS-CHAPv2 and EAP methods
    /// that emit an MSK. Feeds the SSTP Crypto Binding HLAK
    /// ([MS-SSTP] §3.2.5.2).
    pub mppe_send_key: Vec<u8>,
    /// MPPE Recv key (RFC 3079) — peer-to-server.
    pub mppe_recv_key: Vec<u8>,
}

/// Reason an Access-Request did not yield an Access-Accept.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// RADIUS server returned Access-Reject. The optional `Reply-Message`
    /// is forwarded for logging.
    #[error("access rejected: {0:?}")]
    Rejected(Option<String>),
    /// RADIUS server returned Access-Challenge but we cannot satisfy it.
    /// EAP plumbing will turn this into a multi-round-trip eventually.
    #[error("unexpected Access-Challenge")]
    UnexpectedChallenge,
    /// Access-Accept arrived but is missing a mandatory attribute
    /// (currently `Framed-IP-Address`).
    #[error("access accepted but missing attribute: {0}")]
    MissingAttribute(&'static str),
    /// Wire / transport problem.
    #[error("transport: {0}")]
    Transport(#[from] client::TransportError),
    /// Reply could not be parsed.
    #[error("malformed reply: {0}")]
    Malformed(&'static str),
}

/// Configuration for a single RADIUS auth server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    /// Shared secret; held in a `Vec<u8>` rather than a `String` so it
    /// can be zeroized on drop later without UTF-8 assumptions.
    pub secret: Vec<u8>,
}
