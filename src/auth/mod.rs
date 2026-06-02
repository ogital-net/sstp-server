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

pub mod accounting;
pub mod acct_bridge;
pub mod bridge;
pub mod client;
pub mod coa;
pub mod reply;
pub mod request;
pub mod route;

pub use route::FramedRoute;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Result of a successful RADIUS authentication.
///
/// Populated from the Access-Accept; consumed by the session
/// bring-up path to bind a kernel PPP unit, advertise IPCP options
/// to the peer, and seed the SSTP Crypto Binding HLAK.
#[derive(Debug, Clone)]
#[allow(dead_code)] // FUTURE: framed_netmask/framed_mtu/MPPE keys consumed once non-PAP auth + Crypto Binding HLAK are wired.
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
    /// `MS-CHAP2-Success` body (RFC 2548 §2.3.3): the
    /// `S=<40-hex-chars>` Authenticator-Response string the peer
    /// expects in the PPP CHAP `Success` packet ([RFC 2759] §6).
    /// Populated only for MS-CHAPv2 Access-Accepts; the leading
    /// CHAP-Identifier byte from the VSA has been stripped.
    pub mschap2_success: Option<Vec<u8>>,
    /// Per-session traffic-shaping policy projected from RADIUS
    /// VSAs (today: `Mikrotik-Rate-Limit`, vendor 14988, attr 8).
    /// `None` when the Access-Accept carried no recognised shaping
    /// attribute, or when its value parsed but described no
    /// active rate cap.
    pub shaping: Option<crate::shape::ShapingPolicy>,
    /// Server-pushed routes from any number of `Framed-Route`
    /// (RFC 2865 §5.22) attributes. Installed on the per-session
    /// netdev once IPCP converges; the kernel auto-removes them
    /// when the netdev goes away. Empty when the Access-Accept
    /// carried no parseable `Framed-Route`.
    pub framed_routes: Vec<FramedRoute>,
    /// `Class` (RFC 2865 §5.25) — opaque token the authenticator
    /// expects echoed in every Accounting-Request. Stored verbatim;
    /// length-capped at the RADIUS attribute limit (253 bytes).
    pub class: Option<Vec<u8>>,
    /// `Session-Timeout` (RFC 2865 §5.27) — hard cap on total
    /// session duration. `None` means "no server-imposed cap".
    pub session_timeout: Option<Duration>,
    /// `Idle-Timeout` (RFC 2865 §5.28) — disconnect after this
    /// long without traffic in either direction. Sampled against
    /// the kernel netdev counters at the accounting interim
    /// cadence, so the effective idle granularity is the interim
    /// period (currently 60 s by default). `None` disables the
    /// idle check.
    pub idle_timeout: Option<Duration>,
    /// `Acct-Interim-Interval` (RFC 2869 §5.16) — authoritative
    /// override of the local interim cadence. Sub-30s values are
    /// floored to 30 s to avoid hammering RADIUS on misconfigured
    /// dictionaries (RFC 2869 §5.16 "SHOULD NOT be more frequent
    /// than once a minute" with a hint that 30s is the practical
    /// floor accel-ppp / FreeRADIUS use).
    pub acct_interim_interval: Option<Duration>,
}

/// Side-channel policy attributes from an Access-Accept that the
/// PPP / IPCP layer doesn't care about but the session task needs
/// at bring-up time.
///
/// Kept separate from [`crate::ppp::AssignedAddrs`] so the PPP
/// driver doesn't grow a dependency on netlink, accounting, or
/// shaping types. Constructed once at Accept and consumed by the
/// session task once IPCP converges.
#[derive(Debug, Default, Clone)]
pub struct SessionPolicy {
    /// Server-pushed routes from any number of `Framed-Route`
    /// attributes. Installed on the per-session netdev once IPCP
    /// converges.
    pub framed_routes: Vec<FramedRoute>,
    /// `Class` (RFC 2865 §5.25) — opaque token to echo verbatim
    /// in every Accounting-Request.
    pub class: Option<Vec<u8>>,
    /// `Session-Timeout` (RFC 2865 §5.27).
    pub session_timeout: Option<Duration>,
    /// `Idle-Timeout` (RFC 2865 §5.28).
    pub idle_timeout: Option<Duration>,
    /// `Acct-Interim-Interval` (RFC 2869 §5.16) — clamped to a
    /// 30 s minimum at decode time.
    pub acct_interim_interval: Option<Duration>,
}

impl SessionPolicy {
    /// Project an [`AuthAccept`] into the bring-up-time policy
    /// surface. Cheap; the only allocation is the `framed_routes`
    /// `Vec` clone (typically empty or 1‒3 entries).
    #[must_use]
    pub fn from_accept(accept: &AuthAccept) -> Self {
        Self {
            framed_routes: accept.framed_routes.clone(),
            class: accept.class.clone(),
            session_timeout: accept.session_timeout,
            idle_timeout: accept.idle_timeout,
            acct_interim_interval: accept.acct_interim_interval,
        }
    }
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
#[allow(dead_code)] // FUTURE: per-server `ServerConfig` consumed once the multi-server bridge is configured beyond a single `--radius` flag.
pub struct ServerConfig {
    pub addr: SocketAddr,
    /// Shared secret; held in a `Vec<u8>` rather than a `String` so it
    /// can be zeroized on drop later without UTF-8 assumptions.
    pub secret: Vec<u8>,
}
