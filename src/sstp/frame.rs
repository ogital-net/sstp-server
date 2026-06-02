//! SSTP packet header and control-packet framing ([MS-SSTP] §2.2.1–2.2.3).
//!
//! Wire layout (network byte order):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Version    |  Reserved   |C|   R   |        Length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Data ...                             |
//! ```
//!
//! `Version` is fixed at 0x10 (1.0). `C=1` => control packet, `C=0` =>
//! data packet (PPP). `Length` is 12 bits, includes the 4-byte header,
//! so payload length is `Length - 4` and the maximum packet size is
//! `2^12 - 1 = 4095` bytes.

use super::msg::MessageType;

/// `Version` field value for SSTP 1.0.
pub const SSTP_VERSION_1_0: u8 = 0x10;

/// Length of the outer SSTP packet header in bytes.
pub const SSTP_HEADER_LEN: usize = 4;

/// Length of the additional control-packet header (Message Type + Num
/// Attributes), on top of the 4-byte outer header.
pub const SSTP_CONTROL_EXTRA_LEN: usize = 4;

/// Maximum `Length` field value (12 bits, includes header).
pub const SSTP_MAX_PACKET_LEN: usize = 0x0FFF;

/// Errors produced by the zero-copy parser. These cover wire-format
/// violations; the caller maps them to the appropriate SSTP
/// `Status-Info` codes ([MS-SSTP] §2.2.8) or PPP teardown.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("packet shorter than SSTP header")]
    Truncated,
    #[error("unsupported SSTP version 0x{0:02x} (only 0x10 supported)")]
    UnsupportedVersion(u8),
    #[error("declared length {declared} exceeds buffer length {available}")]
    LengthMismatch { declared: usize, available: usize },
    #[error("declared length {0} smaller than header")]
    LengthTooSmall(usize),
    #[error("unknown SSTP message type 0x{0:04x}")]
    UnknownMessageType(u16),
    #[error("unknown SSTP attribute id 0x{0:02x}")]
    UnknownAttributeId(u8),
    #[error("attribute declared length {declared} invalid (available {available})")]
    AttributeLength { declared: usize, available: usize },
    #[error("attribute payload size {actual} does not match expected {expected}")]
    AttributeSize { actual: usize, expected: usize },
}

/// A parsed SSTP packet borrowing its payload from the source buffer.
#[derive(Debug)]
pub enum Packet<'a> {
    /// Data packet — payload is a raw PPP frame ([MS-SSTP] §2.2.3).
    Data(&'a [u8]),
    /// Control packet ([MS-SSTP] §2.2.2).
    Control(ControlPacket<'a>),
}

impl<'a> Packet<'a> {
    /// Parse a single SSTP packet from the head of `buf`.
    ///
    /// Returns the parsed packet and the number of bytes it consumed
    /// (always equal to the `Length` field).
    pub fn parse(buf: &'a [u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < SSTP_HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let version = buf[0];
        if version != SSTP_VERSION_1_0 {
            return Err(ParseError::UnsupportedVersion(version));
        }
        // Reserved (7 bits, ignored) + C (LSB).
        let c = (buf[1] & 0x01) != 0;
        // LengthPacket: high 4 bits reserved, low 12 bits = total length.
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize & SSTP_MAX_PACKET_LEN;
        if length < SSTP_HEADER_LEN {
            return Err(ParseError::LengthTooSmall(length));
        }
        if length > buf.len() {
            return Err(ParseError::LengthMismatch {
                declared: length,
                available: buf.len(),
            });
        }
        let body = &buf[SSTP_HEADER_LEN..length];
        if c {
            Ok((Self::Control(ControlPacket::parse_body(body)?), length))
        } else {
            Ok((Self::Data(body), length))
        }
    }
}

/// SSTP control packet ([MS-SSTP] §2.2.2). `attrs` is the unparsed
/// attribute area; iterate with [`super::AttrIter`].
#[derive(Debug)]
pub struct ControlPacket<'a> {
    pub msg_type: MessageType,
    #[allow(dead_code)] // Used in tests; downstream consumers iterate `attrs` directly.
    pub num_attrs: u16,
    pub attrs: &'a [u8],
}

impl<'a> ControlPacket<'a> {
    /// Parse a control packet body (everything after the 4-byte outer
    /// header). Caller has already validated the length.
    pub(crate) fn parse_body(body: &'a [u8]) -> Result<Self, ParseError> {
        if body.len() < SSTP_CONTROL_EXTRA_LEN {
            return Err(ParseError::Truncated);
        }
        let msg_type_raw = u16::from_be_bytes([body[0], body[1]]);
        let msg_type = MessageType::from_u16(msg_type_raw)
            .ok_or(ParseError::UnknownMessageType(msg_type_raw))?;
        let num_attrs = u16::from_be_bytes([body[2], body[3]]);
        Ok(Self {
            msg_type,
            num_attrs,
            attrs: &body[SSTP_CONTROL_EXTRA_LEN..],
        })
    }
}

/// Write the 4-byte outer SSTP header into `buf[..4]`.
///
/// `total_len` is the full packet length (header + payload) and must
/// fit in 12 bits.
pub fn write_header(buf: &mut [u8; SSTP_HEADER_LEN], control: bool, total_len: usize) {
    debug_assert!(total_len <= SSTP_MAX_PACKET_LEN);
    buf[0] = SSTP_VERSION_1_0;
    buf[1] = u8::from(control); // Reserved (7) || C (1)
    // `total_len <= 0xFFF` (asserted above) fits in a u16; mask is a
    // belt-and-braces guard so a bogus caller can never poison the
    // reserved high 4 bits.
    #[allow(clippy::cast_possible_truncation)]
    let len = (total_len as u16) & (SSTP_MAX_PACKET_LEN as u16);
    buf[2..4].copy_from_slice(&len.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_data_packet() {
        // Version 0x10, C=0, Length=8, then 4 bytes of PPP payload.
        let buf = [0x10, 0x00, 0x00, 0x08, 0xff, 0x03, 0xc0, 0x21];
        let (pkt, used) = Packet::parse(&buf).unwrap();
        assert_eq!(used, 8);
        match pkt {
            Packet::Data(d) => assert_eq!(d, &[0xff, 0x03, 0xc0, 0x21]),
            Packet::Control(_) => panic!("expected data"),
        }
    }

    #[test]
    fn parse_control_packet_no_attrs() {
        // Echo-Request: control, length 8, msg 0x0008, num_attrs 0.
        let buf = [0x10, 0x01, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00];
        let (pkt, used) = Packet::parse(&buf).unwrap();
        assert_eq!(used, 8);
        match pkt {
            Packet::Control(c) => {
                assert_eq!(c.msg_type, MessageType::EchoRequest);
                assert_eq!(c.num_attrs, 0);
                assert!(c.attrs.is_empty());
            }
            Packet::Data(_) => panic!("expected control"),
        }
    }

    #[test]
    fn rejects_bad_version() {
        let buf = [0x20, 0x00, 0x00, 0x04];
        assert_eq!(
            Packet::parse(&buf).unwrap_err(),
            ParseError::UnsupportedVersion(0x20)
        );
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = [0x10, 0x00];
        assert_eq!(Packet::parse(&buf).unwrap_err(), ParseError::Truncated);
    }

    #[test]
    fn rejects_length_overflowing_buffer() {
        // Claims length 16 but buffer is 8.
        let buf = [0x10, 0x00, 0x00, 0x10, 0, 0, 0, 0];
        assert!(matches!(
            Packet::parse(&buf).unwrap_err(),
            ParseError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn ignores_reserved_high_bits_of_length() {
        // Set the reserved upper 4 bits; should still parse Length=8.
        let buf = [0x10, 0x00, 0xf0, 0x08, 1, 2, 3, 4];
        let (pkt, used) = Packet::parse(&buf).unwrap();
        assert_eq!(used, 8);
        match pkt {
            Packet::Data(d) => assert_eq!(d, &[1, 2, 3, 4]),
            Packet::Control(_) => panic!(),
        }
    }

    #[test]
    fn write_header_roundtrip() {
        let mut hdr = [0u8; SSTP_HEADER_LEN];
        write_header(&mut hdr, true, 0x070);
        assert_eq!(hdr, [0x10, 0x01, 0x00, 0x70]);
    }
}
