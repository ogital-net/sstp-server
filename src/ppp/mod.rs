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
#![allow(dead_code, unused_imports)]

pub mod frame;
pub mod fsm;
pub mod lcp;
pub mod auth;
pub mod ipcp;

pub use frame::{
    ADDRESS_ALL_STATIONS, CONTROL_UI, FrameError, PppFrame, ProtocolId, decode_frame, encode_frame,
    encode_frame_compressed,
};
pub use lcp::{
    ConfigOption, ConfigOptionIter, LcpCode, LcpOptionId, LcpPacket, LcpPacketError,
    decode_lcp_packet,
};
