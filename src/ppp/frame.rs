//! PPP frame layer used inside an SSTP data packet.
//!
//! [RFC 1661] §2 defines the PPP frame as:
//!
//! ```text
//!   +----------+----------+----------+--------------+----+
//!   | Address  | Control  | Protocol |    Info      | etc|
//!   |  0xFF    |  0x03    | 8 or 16  |              |    |
//!   +----------+----------+----------+--------------+----+
//! ```
//!
//! SSTP carries the frame raw (no HDLC framing, no FCS — length comes
//! from the enclosing SSTP data packet header per [MS-SSTP] §2.2.3).
//! `ACFC` (Address-and-Control-Field-Compression, [RFC 1661] §6.6)
//! and `PFC` (Protocol-Field-Compression, §6.5) let either field
//! shrink once both peers have acknowledged the option in LCP. We
//! decode either form on receive and choose the encoded form per
//! direction based on what the local LCP layer negotiated.

/// PPP HDLC-broadcast Address byte ([RFC 1662] §3.1).
pub const ADDRESS_ALL_STATIONS: u8 = 0xFF;
/// PPP Control byte: Unnumbered Information (UI) ([RFC 1662] §3.1).
pub const CONTROL_UI: u8 = 0x03;

/// PPP Protocol IDs we care about. Values from the IANA PPP
/// NUMBERS registry; the subset here is what SSTP / RADIUS / EAP need.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolId {
    Ip = 0x0021,
    Ipv6 = 0x0057,
    /// IP Control Protocol ([RFC 1332]).
    Ipcp = 0x8021,
    /// IPv6 Control Protocol ([RFC 5072]).
    Ipv6cp = 0x8057,
    /// Link Control Protocol ([RFC 1661]).
    Lcp = 0xC021,
    /// Password Authentication Protocol ([RFC 1334] §2).
    Pap = 0xC023,
    /// Challenge Handshake Authentication Protocol ([RFC 1994]).
    Chap = 0xC223,
    /// Extensible Authentication Protocol ([RFC 2284] / [RFC 3748]).
    Eap = 0xC227,
}

impl ProtocolId {
    /// Decode an IANA protocol value. Unknown values are returned as
    /// `None`; the caller should send a PPP Protocol-Reject ([RFC 1661]
    /// §5.7) for any frame we don't claim to understand.
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0021 => Some(Self::Ip),
            0x0057 => Some(Self::Ipv6),
            0x8021 => Some(Self::Ipcp),
            0x8057 => Some(Self::Ipv6cp),
            0xC021 => Some(Self::Lcp),
            0xC023 => Some(Self::Pap),
            0xC223 => Some(Self::Chap),
            0xC227 => Some(Self::Eap),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Network-layer protocols ([RFC 1661] §3.2 "Network-Layer
    /// Protocol Phase"). PPP forwards these only after LCP Opened and
    /// authentication completed. Used by [`crate::session`]'s
    /// NP-mode filter to drop IP / IPv6 frames received before
    /// IPCP / IPV6CP converges.
    #[must_use]
    pub const fn is_network_layer(self) -> bool {
        matches!(self, Self::Ip | Self::Ipv6)
    }
}

/// Errors from decoding a PPP frame out of an SSTP data packet payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("PPP frame truncated: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    /// Protocol field's least significant bit must be 0 in the high
    /// byte and 1 in the low byte ([RFC 1661] §2 "Protocol Field").
    /// Anything else is malformed.
    #[error("PPP protocol field 0x{0:04x} has illegal parity")]
    BadProtocolParity(u16),
}

/// A parsed PPP frame borrowing the original payload buffer.
#[derive(Debug, Clone, Copy)]
pub struct PppFrame<'a> {
    pub protocol: u16,
    pub info: &'a [u8],
}

/// Decode a PPP frame from the payload of an SSTP data packet,
/// accepting either compressed or uncompressed Address/Control and
/// Protocol fields.
///
/// Per [RFC 1661] §2: the high byte of Protocol has its low bit = 0,
/// the low byte has its low bit = 1. We use that to distinguish a
/// 1-byte from a 2-byte Protocol field even when PFC is in effect.
pub fn decode_frame(buf: &[u8]) -> Result<PppFrame<'_>, FrameError> {
    let mut p = buf;
    // Optional Address (0xFF) + Control (0x03) prefix. Strip if
    // present; either both bytes are there or neither (ACFC).
    if p.len() >= 2 && p[0] == ADDRESS_ALL_STATIONS && p[1] == CONTROL_UI {
        p = &p[2..];
    }
    if p.is_empty() {
        return Err(FrameError::Truncated {
            need: 1,
            have: buf.len(),
        });
    }
    // Protocol field: 1 byte if low bit is 1 (compressed) else 2.
    let (protocol, rest) = if p[0] & 0x01 == 0x01 {
        (u16::from(p[0]), &p[1..])
    } else {
        if p.len() < 2 {
            return Err(FrameError::Truncated {
                need: 2,
                have: p.len(),
            });
        }
        let v = u16::from_be_bytes([p[0], p[1]]);
        // High byte even, low byte odd.
        if v & 0x0101 != 0x0001 {
            return Err(FrameError::BadProtocolParity(v));
        }
        (v, &p[2..])
    };
    Ok(PppFrame {
        protocol,
        info: rest,
    })
}

/// Encode a PPP frame with the *uncompressed* header: Address +
/// Control + 2-byte Protocol. This is the always-safe form, used
/// before LCP has opened and any time the peer has not acknowledged
/// both `ACFC` and `PFC`.
///
/// Returns the number of bytes written. Caller is responsible for
/// sizing `out` to at least `4 + info.len()`.
pub fn encode_frame(out: &mut [u8], protocol: u16, info: &[u8]) -> usize {
    let need = 4 + info.len();
    assert!(out.len() >= need, "PPP encode buffer too small");
    out[0] = ADDRESS_ALL_STATIONS;
    out[1] = CONTROL_UI;
    out[2..4].copy_from_slice(&protocol.to_be_bytes());
    out[4..need].copy_from_slice(info);
    need
}

/// Encode a PPP frame with ACFC + PFC applied where legal: omits the
/// Address/Control prefix; uses a 1-byte Protocol field iff the
/// Protocol value fits in 8 bits ([RFC 1661] §6.5 — only protocols
/// 0x00–0xFF are eligible).
///
/// Caller must only use this once LCP has negotiated both options.
#[allow(dead_code)] // FUTURE: caller selects compressed encoding once Address/Control/Protocol-Field-Compression LCP options are negotiated.
pub fn encode_frame_compressed(out: &mut [u8], protocol: u16, info: &[u8]) -> usize {
    if protocol <= 0xFF {
        let need = 1 + info.len();
        assert!(out.len() >= need, "PPP encode buffer too small");
        #[allow(clippy::cast_possible_truncation)]
        {
            out[0] = protocol as u8;
        }
        out[1..need].copy_from_slice(info);
        need
    } else {
        let need = 2 + info.len();
        assert!(out.len() >= need, "PPP encode buffer too small");
        out[0..2].copy_from_slice(&protocol.to_be_bytes());
        out[2..need].copy_from_slice(info);
        need
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_id_roundtrip() {
        for p in [
            ProtocolId::Ip,
            ProtocolId::Ipv6,
            ProtocolId::Ipcp,
            ProtocolId::Ipv6cp,
            ProtocolId::Lcp,
            ProtocolId::Pap,
            ProtocolId::Chap,
            ProtocolId::Eap,
        ] {
            assert_eq!(ProtocolId::from_u16(p.as_u16()), Some(p));
        }
        assert_eq!(ProtocolId::from_u16(0x1234), None);
    }

    #[test]
    fn decode_uncompressed_lcp() {
        let buf = [0xff, 0x03, 0xc0, 0x21, 0x01, 0x02, 0x03];
        let f = decode_frame(&buf).unwrap();
        assert_eq!(f.protocol, 0xC021);
        assert_eq!(f.info, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn decode_acfc_only() {
        let buf = [0xc0, 0x21, 0x01, 0x02];
        let f = decode_frame(&buf).unwrap();
        assert_eq!(f.protocol, 0xC021);
        assert_eq!(f.info, &[0x01, 0x02]);
    }

    #[test]
    fn decode_pfc_compressed() {
        // Protocol 0x21 (IP, compressed).
        let buf = [0xff, 0x03, 0x21, 0xde, 0xad];
        let f = decode_frame(&buf).unwrap();
        assert_eq!(f.protocol, 0x0021);
        assert_eq!(f.info, &[0xde, 0xad]);
    }

    #[test]
    fn decode_acfc_and_pfc() {
        let buf = [0x21, 0xaa];
        let f = decode_frame(&buf).unwrap();
        assert_eq!(f.protocol, 0x0021);
        assert_eq!(f.info, &[0xaa]);
    }

    #[test]
    fn rejects_bad_parity() {
        // First byte LSB=0 → 2-byte form; second byte LSB=0 → illegal.
        let buf = [0xff, 0x03, 0xc0, 0x20];
        assert!(matches!(
            decode_frame(&buf),
            Err(FrameError::BadProtocolParity(_))
        ));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            decode_frame(&[]),
            Err(FrameError::Truncated { .. })
        ));
    }

    #[test]
    fn encode_uncompressed_roundtrip() {
        let mut out = [0u8; 16];
        let n = encode_frame(&mut out, 0xC021, &[0x01, 0x02, 0x03]);
        assert_eq!(n, 7);
        assert_eq!(&out[..n], &[0xff, 0x03, 0xc0, 0x21, 0x01, 0x02, 0x03]);
        let f = decode_frame(&out[..n]).unwrap();
        assert_eq!(f.protocol, 0xC021);
        assert_eq!(f.info, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn encode_compressed_ip() {
        let mut out = [0u8; 16];
        let n = encode_frame_compressed(&mut out, 0x0021, &[0xaa]);
        assert_eq!(n, 2);
        assert_eq!(&out[..n], &[0x21, 0xaa]);
    }

    #[test]
    fn encode_compressed_lcp_stays_two_bytes() {
        let mut out = [0u8; 16];
        let n = encode_frame_compressed(&mut out, 0xC021, &[0x01]);
        assert_eq!(n, 3);
        assert_eq!(&out[..n], &[0xc0, 0x21, 0x01]);
    }
}
