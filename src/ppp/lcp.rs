//! Link Control Protocol packets ([RFC 1661] §5, §6).
//!
//! This module covers parsing and encoding of LCP packets and their
//! configuration options. The Option-Negotiation FSM that drives them
//! ([RFC 1661] §4.2) lives in a sibling module so the codec stays
//! free of state.

// Some negotiation accessors (`as_mru`, `as_magic_number`,
// `as_auth_protocol`, `is_configure`) and the `auth_protocol_eap`
// builder are scaffolding for the future EAP pass-through phase.
// PAP, CHAP-MD5, and MS-CHAPv2 negotiation are wired today.
#![allow(dead_code)]

use super::frame::ProtocolId;

/// LCP packet header length (Code + Identifier + Length).
pub const LCP_HEADER_LEN: usize = 4;

/// LCP option header length (Type + Length).
pub const LCP_OPT_HEADER_LEN: usize = 2;

/// Default Maximum Receive Unit when MRU isn't negotiated
/// ([RFC 1661] §6.1).
pub const DEFAULT_MRU: u16 = 1500;

/// LCP packet codes from [RFC 1661] §5 (and §5.8 Code-Reject /
/// §5.7 Protocol-Reject / §5.9–5.11 Echo + Discard).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcpCode {
    ConfigureRequest = 1,
    ConfigureAck = 2,
    ConfigureNak = 3,
    ConfigureReject = 4,
    TerminateRequest = 5,
    TerminateAck = 6,
    CodeReject = 7,
    ProtocolReject = 8,
    EchoRequest = 9,
    EchoReply = 10,
    DiscardRequest = 11,
}

impl LcpCode {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ConfigureRequest),
            2 => Some(Self::ConfigureAck),
            3 => Some(Self::ConfigureNak),
            4 => Some(Self::ConfigureReject),
            5 => Some(Self::TerminateRequest),
            6 => Some(Self::TerminateAck),
            7 => Some(Self::CodeReject),
            8 => Some(Self::ProtocolReject),
            9 => Some(Self::EchoRequest),
            10 => Some(Self::EchoReply),
            11 => Some(Self::DiscardRequest),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// True for the four packets that carry a list of TLV options
    /// ([RFC 1661] §5.1–5.4); false for the bare-payload codes.
    #[must_use]
    pub const fn is_configure(self) -> bool {
        matches!(
            self,
            Self::ConfigureRequest
                | Self::ConfigureAck
                | Self::ConfigureNak
                | Self::ConfigureReject
        )
    }
}

/// LCP configuration option types from [RFC 1661] §6 (and [RFC 1570]
/// for the auth additions). Only the ones SSTP actually negotiates.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcpOptionId {
    /// Maximum Receive Unit ([RFC 1661] §6.1). 2 bytes.
    Mru = 1,
    /// Authentication Protocol ([RFC 1661] §6.2). 2-byte protocol
    /// followed by per-protocol data (e.g. CHAP algorithm).
    AuthProtocol = 3,
    /// Quality Protocol ([RFC 1661] §6.3). We reject unconditionally.
    QualityProtocol = 4,
    /// Magic Number ([RFC 1661] §6.4). 4 bytes.
    MagicNumber = 5,
    /// Protocol Field Compression ([RFC 1661] §6.5). 0-byte value.
    ProtocolFieldCompression = 7,
    /// Address-and-Control-Field Compression ([RFC 1661] §6.6). 0-byte.
    AddressControlFieldCompression = 8,
}

impl LcpOptionId {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Mru),
            3 => Some(Self::AuthProtocol),
            4 => Some(Self::QualityProtocol),
            5 => Some(Self::MagicNumber),
            7 => Some(Self::ProtocolFieldCompression),
            8 => Some(Self::AddressControlFieldCompression),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Errors when decoding an LCP packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LcpPacketError {
    #[error("LCP packet truncated: need {need}, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("LCP Length {declared} smaller than header (4)")]
    LengthTooSmall { declared: usize },
    #[error("LCP Length {declared} exceeds buffer ({available})")]
    LengthExceedsBuffer { declared: usize, available: usize },
    #[error("LCP option Length {declared} smaller than header (2)")]
    OptionLengthTooSmall { declared: usize },
    #[error("LCP option Length {declared} exceeds remaining ({available})")]
    OptionLengthExceedsBuffer { declared: usize, available: usize },
}

/// A parsed LCP packet borrowing the underlying buffer.
///
/// `data` is everything after the 4-byte header: an option list for
/// Configure-* / Code-Reject, a rejected-packet payload for
/// Code-Reject / Protocol-Reject, or a Magic-Number + data tail for
/// Echo / Discard. Higher layers re-parse `data` based on `code`.
#[derive(Debug, Clone, Copy)]
pub struct LcpPacket<'a> {
    pub code: u8,
    pub identifier: u8,
    pub data: &'a [u8],
}

impl LcpPacket<'_> {
    /// Typed view of `code` if it's one we know.
    #[must_use]
    pub fn typed_code(&self) -> Option<LcpCode> {
        LcpCode::from_u8(self.code)
    }
}

/// Decode the LCP header and return a view bounded by its declared
/// Length.
pub fn decode_lcp_packet(buf: &[u8]) -> Result<LcpPacket<'_>, LcpPacketError> {
    if buf.len() < LCP_HEADER_LEN {
        return Err(LcpPacketError::Truncated {
            need: LCP_HEADER_LEN,
            have: buf.len(),
        });
    }
    let code = buf[0];
    let identifier = buf[1];
    let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if declared < LCP_HEADER_LEN {
        return Err(LcpPacketError::LengthTooSmall { declared });
    }
    if declared > buf.len() {
        return Err(LcpPacketError::LengthExceedsBuffer {
            declared,
            available: buf.len(),
        });
    }
    Ok(LcpPacket {
        code,
        identifier,
        data: &buf[LCP_HEADER_LEN..declared],
    })
}

/// One TLV option from a Configure-* packet's option list.
#[derive(Debug, Clone, Copy)]
pub struct ConfigOption<'a> {
    pub option_type: u8,
    pub value: &'a [u8],
}

impl<'a> ConfigOption<'a> {
    /// Total on-wire length (header + value).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        LCP_OPT_HEADER_LEN + self.value.len()
    }

    /// Typed view of `option_type` if we recognise it.
    #[must_use]
    pub fn typed(&self) -> Option<LcpOptionId> {
        LcpOptionId::from_u8(self.option_type)
    }

    /// Decode an MRU option ([RFC 1661] §6.1).
    pub fn as_mru(&self) -> Result<u16, LcpPacketError> {
        if self.value.len() != 2 {
            return Err(LcpPacketError::OptionLengthTooSmall {
                declared: self.value.len() + LCP_OPT_HEADER_LEN,
            });
        }
        Ok(u16::from_be_bytes([self.value[0], self.value[1]]))
    }

    /// Decode a Magic-Number option ([RFC 1661] §6.4).
    pub fn as_magic_number(&self) -> Result<u32, LcpPacketError> {
        if self.value.len() != 4 {
            return Err(LcpPacketError::OptionLengthTooSmall {
                declared: self.value.len() + LCP_OPT_HEADER_LEN,
            });
        }
        Ok(u32::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]))
    }

    /// Decode the Authentication-Protocol option ([RFC 1661] §6.2).
    /// Returns the 2-byte protocol id and any per-protocol payload
    /// (e.g. CHAP algorithm byte, [RFC 1994] §3).
    pub fn as_auth_protocol(&self) -> Result<(u16, &'a [u8]), LcpPacketError> {
        if self.value.len() < 2 {
            return Err(LcpPacketError::OptionLengthTooSmall {
                declared: self.value.len() + LCP_OPT_HEADER_LEN,
            });
        }
        let proto = u16::from_be_bytes([self.value[0], self.value[1]]);
        Ok((proto, &self.value[2..]))
    }
}

/// Iterator over a Configure-* packet's option list, yielding
/// [`ConfigOption`] views. Stops on the first malformed option and
/// surfaces the error.
pub struct ConfigOptionIter<'a> {
    cursor: &'a [u8],
}

impl<'a> ConfigOptionIter<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { cursor: buf }
    }
}

impl<'a> Iterator for ConfigOptionIter<'a> {
    type Item = Result<ConfigOption<'a>, LcpPacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.is_empty() {
            return None;
        }
        if self.cursor.len() < LCP_OPT_HEADER_LEN {
            let have = self.cursor.len();
            self.cursor = &[];
            return Some(Err(LcpPacketError::Truncated {
                need: LCP_OPT_HEADER_LEN,
                have,
            }));
        }
        let option_type = self.cursor[0];
        let declared = self.cursor[1] as usize;
        if declared < LCP_OPT_HEADER_LEN {
            self.cursor = &[];
            return Some(Err(LcpPacketError::OptionLengthTooSmall { declared }));
        }
        if declared > self.cursor.len() {
            let available = self.cursor.len();
            self.cursor = &[];
            return Some(Err(LcpPacketError::OptionLengthExceedsBuffer {
                declared,
                available,
            }));
        }
        let value = &self.cursor[LCP_OPT_HEADER_LEN..declared];
        self.cursor = &self.cursor[declared..];
        Some(Ok(ConfigOption { option_type, value }))
    }
}

/// Encode an LCP header at the start of `out`. Returns
/// [`LCP_HEADER_LEN`].
///
/// `total_len` is the full packet length (header + payload). The
/// caller is responsible for already having written the payload in
/// place after the header.
#[allow(clippy::cast_possible_truncation)]
pub fn write_lcp_header(out: &mut [u8; LCP_HEADER_LEN], code: u8, identifier: u8, total_len: u16) {
    out[0] = code;
    out[1] = identifier;
    out[2..4].copy_from_slice(&total_len.to_be_bytes());
}

/// Encode a single TLV option into `out`. Returns the number of bytes
/// written (always `LCP_OPT_HEADER_LEN + value.len()`).
///
/// Caller must size `out` to at least that. Panics in debug if the
/// option is longer than 255 bytes (LCP Length is one byte).
pub fn write_option(out: &mut [u8], option_type: u8, value: &[u8]) -> usize {
    let total = LCP_OPT_HEADER_LEN + value.len();
    assert!(out.len() >= total, "LCP option buffer too small");
    debug_assert!(u8::try_from(total).is_ok(), "LCP option too long");
    out[0] = option_type;
    #[allow(clippy::cast_possible_truncation)]
    {
        out[1] = total as u8;
    }
    out[LCP_OPT_HEADER_LEN..total].copy_from_slice(value);
    total
}

/// Build an `Authentication-Protocol` option value for an auth method.
/// The returned tuple is `(option payload bytes, payload length)`
/// suitable to pass into [`write_option`] as `value`.
#[must_use]
pub fn auth_protocol_pap() -> [u8; 2] {
    ProtocolId::Pap.as_u16().to_be_bytes()
}

/// MS-CHAPv2 advertises with the CHAP protocol id and algorithm
/// byte 0x81 ([MS-CHAP] §1.5 / IANA "PPP CHAP Algorithm").
#[must_use]
pub fn auth_protocol_mschapv2() -> [u8; 3] {
    let mut v = [0u8; 3];
    v[0..2].copy_from_slice(&ProtocolId::Chap.as_u16().to_be_bytes());
    v[2] = 0x81;
    v
}

/// CHAP-MD5 ([RFC 1994] §3): CHAP protocol id (0xC223) + algorithm
/// byte 0x05.
#[must_use]
pub fn auth_protocol_chap_md5() -> [u8; 3] {
    let mut v = [0u8; 3];
    v[0..2].copy_from_slice(&ProtocolId::Chap.as_u16().to_be_bytes());
    v[2] = 0x05;
    v
}

#[must_use]
pub fn auth_protocol_eap() -> [u8; 2] {
    ProtocolId::Eap.as_u16().to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_configure_request_with_options() {
        // Code=1 (ConfReq), Id=42, Length=14
        //   Option MRU = 1500   (type 1, len 4, value 0x05DC)
        //   Option MagicNumber  (type 5, len 6, value 0xDEADBEEF)
        let buf = [
            0x01, 0x2a, 0x00, 0x0e, // header
            0x01, 0x04, 0x05, 0xdc, // MRU = 1500
            0x05, 0x06, 0xde, 0xad, 0xbe, 0xef, // Magic
        ];
        let pkt = decode_lcp_packet(&buf).unwrap();
        assert_eq!(pkt.typed_code(), Some(LcpCode::ConfigureRequest));
        assert_eq!(pkt.identifier, 42);
        let opts: Vec<_> = ConfigOptionIter::new(pkt.data)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].typed(), Some(LcpOptionId::Mru));
        assert_eq!(opts[0].as_mru().unwrap(), 1500);
        assert_eq!(opts[1].typed(), Some(LcpOptionId::MagicNumber));
        assert_eq!(opts[1].as_magic_number().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn decode_zero_length_options() {
        // ConfReq with PFC + ACFC.
        let buf = [
            0x01, 0x01, 0x00, 0x08, // header, Length=8
            0x07, 0x02, // PFC, len 2
            0x08, 0x02, // ACFC, len 2
        ];
        let pkt = decode_lcp_packet(&buf).unwrap();
        let opts: Vec<_> = ConfigOptionIter::new(pkt.data)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].typed(), Some(LcpOptionId::ProtocolFieldCompression));
        assert_eq!(opts[0].value.len(), 0);
        assert_eq!(
            opts[1].typed(),
            Some(LcpOptionId::AddressControlFieldCompression)
        );
    }

    #[test]
    fn decode_auth_protocol_chap_mschapv2() {
        let buf = [
            0x01, 0x05, 0x00, 0x09, // header, Length=9
            0x03, 0x05, 0xc2, 0x23, 0x81, // Auth = CHAP/MS-CHAPv2
        ];
        let pkt = decode_lcp_packet(&buf).unwrap();
        let opt = ConfigOptionIter::new(pkt.data).next().unwrap().unwrap();
        let (proto, tail) = opt.as_auth_protocol().unwrap();
        assert_eq!(proto, 0xC223);
        assert_eq!(tail, &[0x81]);
    }

    #[test]
    fn rejects_short_packet() {
        assert!(matches!(
            decode_lcp_packet(&[0x01, 0x00, 0x00]),
            Err(LcpPacketError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_length_below_header() {
        assert!(matches!(
            decode_lcp_packet(&[0x01, 0x00, 0x00, 0x03]),
            Err(LcpPacketError::LengthTooSmall { declared: 3 })
        ));
    }

    #[test]
    fn rejects_length_overflowing_buffer() {
        assert!(matches!(
            decode_lcp_packet(&[0x01, 0x00, 0x00, 0x40, 0x00, 0x00]),
            Err(LcpPacketError::LengthExceedsBuffer {
                declared: 0x40,
                available: 6
            })
        ));
    }

    #[test]
    fn option_iter_surfaces_bad_length() {
        // Option type 5, declared len 1 → too small.
        let opts: Vec<_> = ConfigOptionIter::new(&[0x05, 0x01]).collect();
        assert!(matches!(
            opts[0],
            Err(LcpPacketError::OptionLengthTooSmall { declared: 1 })
        ));
    }

    #[test]
    fn write_header_and_option() {
        let mut buf = [0u8; LCP_HEADER_LEN + 6];
        let opt_len = write_option(&mut buf[LCP_HEADER_LEN..], 5, &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(opt_len, 6);
        let total = LCP_HEADER_LEN + opt_len;
        let (head, _) = buf.split_at_mut(LCP_HEADER_LEN);
        let head4: &mut [u8; LCP_HEADER_LEN] = head.try_into().unwrap();
        write_lcp_header(
            head4,
            LcpCode::ConfigureRequest.as_u8(),
            7,
            u16::try_from(total).unwrap(),
        );
        assert_eq!(
            &buf[..],
            &[0x01, 0x07, 0x00, 0x0a, 0x05, 0x06, 0x11, 0x22, 0x33, 0x44]
        );
        let pkt = decode_lcp_packet(&buf).unwrap();
        assert_eq!(pkt.identifier, 7);
        let opt = ConfigOptionIter::new(pkt.data).next().unwrap().unwrap();
        assert_eq!(opt.as_magic_number().unwrap(), 0x1122_3344);
    }

    #[test]
    fn auth_protocol_helpers() {
        assert_eq!(auth_protocol_pap(), [0xc0, 0x23]);
        assert_eq!(auth_protocol_mschapv2(), [0xc2, 0x23, 0x81]);
        assert_eq!(auth_protocol_chap_md5(), [0xc2, 0x23, 0x05]);
        assert_eq!(auth_protocol_eap(), [0xc2, 0x27]);
    }
}
