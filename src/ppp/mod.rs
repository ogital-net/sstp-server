//! In-process PPP control plane ([RFC 1661], [RFC 1332], [RFC 2284]).
//!
//! Scope is what SSTP needs: LCP, the authentication phase
//! (dispatching PAP / CHAP / MS-CHAPv2 / EAP fragments out to RADIUS),
//! and IPCP / IPV6CP. This is **not** a general-purpose PPP library —
//! HDLC framing, async-control-character mapping, and the modem-era
//! options are intentionally absent because SSTP carries PPP frames as
//! length-delimited payloads inside SSTP data packets ([MS-SSTP]
//! §2.2.3) rather than as an octet stream.

// Consumers land in M4 (RADIUS bridge) and M5 (kernel PPP plumbing).

pub mod auth;
pub mod driver;
pub mod frame;
pub mod fsm;
pub mod ipcp;
pub mod lcp;

pub use driver::{AssignedAddrs, AuthVerdict, Ppp, PppEvent, PppStep, TimerOwner};
