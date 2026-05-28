//! SSTP control-message types and typed parsers/builders
//! ([MS-SSTP] §2.2.2 and §2.2.9–2.2.15).
//!
//! Parsing is zero-copy: [`ControlMessage`] borrows from the source
//! packet's attribute area. Builders write directly into a caller
//! supplied `&mut [u8]` and return bytes written, so the caller owns
//! all allocation.

use super::attr::{
    self, ATTR_HEADER_LEN, AttrIter, AttributeId, CryptoBinding, CryptoBindingReq, StatusCode,
    write_attr_header,
};
use super::frame::{
    ControlPacket, ParseError, SSTP_CONTROL_EXTRA_LEN, SSTP_HEADER_LEN, write_header,
};

/// SSTP control message type ([MS-SSTP] §2.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    CallConnectRequest = 0x0001,
    CallConnectAck = 0x0002,
    CallConnectNak = 0x0003,
    CallConnected = 0x0004,
    CallAbort = 0x0005,
    CallDisconnect = 0x0006,
    CallDisconnectAck = 0x0007,
    EchoRequest = 0x0008,
    EchoResponse = 0x0009,
}

impl MessageType {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0001 => Self::CallConnectRequest,
            0x0002 => Self::CallConnectAck,
            0x0003 => Self::CallConnectNak,
            0x0004 => Self::CallConnected,
            0x0005 => Self::CallAbort,
            0x0006 => Self::CallDisconnect,
            0x0007 => Self::CallDisconnectAck,
            0x0008 => Self::EchoRequest,
            0x0009 => Self::EchoResponse,
            _ => return None,
        })
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

// -- Typed view of a parsed control message --------------------------------

/// Decoded SSTP control message, borrowing from the source buffer.
///
/// Only the message variants the server actually consumes carry typed
/// payload; the rest expose the raw [`ControlPacket`] so the state
/// machine can decide what to do without paying the parse cost.
#[derive(Debug)]
pub enum ControlMessage<'a> {
    /// §2.2.9 — must carry exactly one Encapsulated-Protocol-Id.
    CallConnectRequest { protocol_id: u16 },
    /// §2.2.11 — must carry exactly one Crypto-Binding attribute.
    CallConnected(CryptoBinding<'a>),
    /// §2.2.14 — Status-Info is OPTIONAL.
    CallDisconnect,
    /// §2.2.15 — never carries attributes.
    CallDisconnectAck,
    /// §2.2.15 — never carries attributes.
    EchoRequest,
    /// §2.2.15 — never carries attributes.
    EchoResponse,
    /// §2.2.13 — Status-Info is OPTIONAL (SHOULD).
    CallAbort,
    /// §2.2.10 / §2.2.12 — server-originated messages; the server
    /// never parses these. Carried opaquely so a client-mode test
    /// harness can hook in later.
    Other(ControlPacket<'a>),
}

/// Parse a [`ControlPacket`] into a typed [`ControlMessage`].
///
/// Enforces per-message attribute constraints from §2.2.9–2.2.15 for
/// the messages a server consumes. Server-originated messages are
/// returned as [`ControlMessage::Other`] without inspecting attributes.
pub fn parse_control(pkt: ControlPacket<'_>) -> Result<ControlMessage<'_>, ParseError> {
    match pkt.msg_type {
        MessageType::CallConnectRequest => {
            let mut it = AttrIter::new(pkt.attrs);
            let first = it.next().ok_or(ParseError::AttributeLength {
                declared: 0,
                available: 0,
            })??;
            let proto = first.as_encapsulated_protocol()?;
            if it.next().is_some() {
                return Err(ParseError::AttributeLength {
                    declared: pkt.attrs.len(),
                    available: ATTR_HEADER_LEN + 2,
                });
            }
            Ok(ControlMessage::CallConnectRequest { protocol_id: proto })
        }
        MessageType::CallConnected => {
            let mut it = AttrIter::new(pkt.attrs);
            let first = it.next().ok_or(ParseError::AttributeLength {
                declared: 0,
                available: 0,
            })??;
            let cb = first.as_crypto_binding()?;
            if it.next().is_some() {
                return Err(ParseError::AttributeLength {
                    declared: pkt.attrs.len(),
                    available: ATTR_HEADER_LEN + CryptoBinding::VALUE_LEN,
                });
            }
            Ok(ControlMessage::CallConnected(cb))
        }
        MessageType::CallDisconnect => Ok(ControlMessage::CallDisconnect),
        MessageType::CallDisconnectAck => Ok(ControlMessage::CallDisconnectAck),
        MessageType::EchoRequest => Ok(ControlMessage::EchoRequest),
        MessageType::EchoResponse => Ok(ControlMessage::EchoResponse),
        MessageType::CallAbort => Ok(ControlMessage::CallAbort),
        MessageType::CallConnectAck | MessageType::CallConnectNak => Ok(ControlMessage::Other(pkt)),
    }
}

// -- Encoders --------------------------------------------------------------

/// Total wire size of a Call Connect Ack ([MS-SSTP] §2.2.10).
pub const CALL_CONNECT_ACK_LEN: usize = 48;
/// Total wire size of a Call Connected message ([MS-SSTP] §2.2.11).
pub const CALL_CONNECTED_LEN: usize = 112;
/// Wire size of a Status-Info attribute with no `AttribValue`.
const STATUS_INFO_FIXED_LEN: usize = ATTR_HEADER_LEN + 8;
/// Wire size of an attribute-free control message.
pub const EMPTY_CONTROL_LEN: usize = SSTP_HEADER_LEN + SSTP_CONTROL_EXTRA_LEN;

fn write_control_extra(buf: &mut [u8; SSTP_CONTROL_EXTRA_LEN], ty: MessageType, num_attrs: u16) {
    buf[0..2].copy_from_slice(&ty.as_u16().to_be_bytes());
    buf[2..4].copy_from_slice(&num_attrs.to_be_bytes());
}

/// Encode a Call Connect Ack ([MS-SSTP] §2.2.10). Returns 48.
pub fn encode_call_connect_ack(out: &mut [u8], hash_bitmask: u8, nonce: &[u8; 32]) -> usize {
    assert!(out.len() >= CALL_CONNECT_ACK_LEN);
    let buf = &mut out[..CALL_CONNECT_ACK_LEN];
    write_header(
        (&mut buf[..SSTP_HEADER_LEN]).try_into().expect("len"),
        true,
        CALL_CONNECT_ACK_LEN,
    );
    write_control_extra(
        (&mut buf[SSTP_HEADER_LEN..SSTP_HEADER_LEN + SSTP_CONTROL_EXTRA_LEN])
            .try_into()
            .expect("len"),
        MessageType::CallConnectAck,
        1,
    );
    // Crypto-Binding-Req attribute starts at offset 8.
    write_attr_header(
        (&mut buf[8..12]).try_into().expect("len"),
        AttributeId::CryptoBindingReq,
        ATTR_HEADER_LEN + CryptoBindingReq::VALUE_LEN,
    );
    buf[12] = 0;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = hash_bitmask;
    buf[16..48].copy_from_slice(nonce);
    CALL_CONNECT_ACK_LEN
}

/// Encode a Call Connect NAK ([MS-SSTP] §2.2.12) with a single
/// Status-Info attribute and no `AttribValue` (20 bytes).
pub fn encode_call_connect_nak(out: &mut [u8], offending_attr: u8, status: StatusCode) -> usize {
    let total = EMPTY_CONTROL_LEN + STATUS_INFO_FIXED_LEN;
    assert!(out.len() >= total);
    write_header(
        (&mut out[..SSTP_HEADER_LEN]).try_into().expect("len"),
        true,
        total,
    );
    write_control_extra(
        (&mut out[SSTP_HEADER_LEN..SSTP_HEADER_LEN + SSTP_CONTROL_EXTRA_LEN])
            .try_into()
            .expect("len"),
        MessageType::CallConnectNak,
        1,
    );
    write_status_info_attr(&mut out[EMPTY_CONTROL_LEN..total], offending_attr, status);
    total
}

/// Encode a Call Abort ([MS-SSTP] §2.2.13).
pub fn encode_call_abort(out: &mut [u8], status_info: Option<(u8, StatusCode)>) -> usize {
    encode_status_info_message(out, MessageType::CallAbort, status_info)
}

/// Encode a Call Disconnect ([MS-SSTP] §2.2.14). When the Status-Info
/// attribute is included, the spec mandates `AttribID=NO_ERROR` and
/// `Status=NO_ERROR`.
pub fn encode_call_disconnect(out: &mut [u8], include_status_info: bool) -> usize {
    let info = include_status_info.then_some((AttributeId::NoError.as_u8(), StatusCode::NoError));
    encode_status_info_message(out, MessageType::CallDisconnect, info)
}

fn encode_status_info_message(
    out: &mut [u8],
    ty: MessageType,
    status_info: Option<(u8, StatusCode)>,
) -> usize {
    let total = EMPTY_CONTROL_LEN + status_info.map_or(0, |_| STATUS_INFO_FIXED_LEN);
    assert!(out.len() >= total);
    write_header(
        (&mut out[..SSTP_HEADER_LEN]).try_into().expect("len"),
        true,
        total,
    );
    let num_attrs = u16::from(status_info.is_some());
    write_control_extra(
        (&mut out[SSTP_HEADER_LEN..SSTP_HEADER_LEN + SSTP_CONTROL_EXTRA_LEN])
            .try_into()
            .expect("len"),
        ty,
        num_attrs,
    );
    if let Some((attrib_id, status)) = status_info {
        write_status_info_attr(&mut out[EMPTY_CONTROL_LEN..total], attrib_id, status);
    }
    total
}

/// Encode a fixed-format empty control message ([MS-SSTP] §2.2.15:
/// Call Disconnect Ack, Echo Request, Echo Response). 8 bytes.
pub fn encode_empty_control(out: &mut [u8], ty: MessageType) -> usize {
    assert!(matches!(
        ty,
        MessageType::CallDisconnectAck | MessageType::EchoRequest | MessageType::EchoResponse
    ));
    assert!(out.len() >= EMPTY_CONTROL_LEN);
    write_header(
        (&mut out[..SSTP_HEADER_LEN]).try_into().expect("len"),
        true,
        EMPTY_CONTROL_LEN,
    );
    write_control_extra(
        (&mut out[SSTP_HEADER_LEN..EMPTY_CONTROL_LEN])
            .try_into()
            .expect("len"),
        ty,
        0,
    );
    EMPTY_CONTROL_LEN
}

fn write_status_info_attr(out: &mut [u8], attrib_id: u8, status: StatusCode) {
    debug_assert!(out.len() >= STATUS_INFO_FIXED_LEN);
    write_attr_header(
        (&mut out[..ATTR_HEADER_LEN]).try_into().expect("len"),
        AttributeId::StatusInfo,
        STATUS_INFO_FIXED_LEN,
    );
    // 3 bytes Reserved2 || 1 byte AttribID || 4 bytes Status
    out[4] = 0;
    out[5] = 0;
    out[6] = 0;
    out[7] = attrib_id;
    out[8..12].copy_from_slice(&(status as u32).to_be_bytes());
}

/// Encode a Call Connected message ([MS-SSTP] §2.2.11) with the
/// Compound MAC zeroed, ready for HMAC computation by the caller
/// (§3.2.5.2.3). After computing the MAC, write it back with
/// [`install_compound_mac`].
pub fn encode_call_connected_pre_mac(
    out: &mut [u8; CALL_CONNECTED_LEN],
    hash_protocol: u8,
    nonce: &[u8; 32],
    cert_hash: &[u8],
) {
    debug_assert!(cert_hash.len() == 20 || cert_hash.len() == 32);
    debug_assert!(
        hash_protocol == attr::CERT_HASH_PROTOCOL_SHA1
            || hash_protocol == attr::CERT_HASH_PROTOCOL_SHA256
    );
    write_header(
        (&mut out[..SSTP_HEADER_LEN]).try_into().expect("len"),
        true,
        CALL_CONNECTED_LEN,
    );
    write_control_extra(
        (&mut out[SSTP_HEADER_LEN..SSTP_HEADER_LEN + SSTP_CONTROL_EXTRA_LEN])
            .try_into()
            .expect("len"),
        MessageType::CallConnected,
        1,
    );
    write_attr_header(
        (&mut out[8..12]).try_into().expect("len"),
        AttributeId::CryptoBinding,
        ATTR_HEADER_LEN + CryptoBinding::VALUE_LEN,
    );
    out[12] = 0;
    out[13] = 0;
    out[14] = 0;
    out[15] = hash_protocol;
    out[16..48].copy_from_slice(nonce);
    let (active, pad) = out[48..80].split_at_mut(cert_hash.len());
    active.copy_from_slice(cert_hash);
    pad.fill(0);
    out[80..112].fill(0); // Compound MAC || Padding1, zeroed for MAC input
}

/// Place a Compound MAC into a previously-encoded Call Connected
/// buffer. `mac` must be 20 bytes (SHA1) or 32 bytes (SHA256); the
/// trailing zero pad is preserved.
pub fn install_compound_mac(buf: &mut [u8; CALL_CONNECTED_LEN], mac: &[u8]) {
    debug_assert!(mac.len() == 20 || mac.len() == 32);
    let mac_field = &mut buf[80..112];
    mac_field.fill(0);
    mac_field[..mac.len()].copy_from_slice(mac);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sstp::attr::{CERT_HASH_PROTOCOL_SHA256, SSTP_ENCAPSULATED_PROTOCOL_PPP};
    use crate::sstp::frame::Packet;

    fn parse_one(buf: &[u8]) -> ControlMessage<'_> {
        let (Packet::Control(c), _) = Packet::parse(buf).unwrap() else {
            panic!("not control");
        };
        parse_control(c).unwrap()
    }

    #[test]
    fn parse_call_connect_request() {
        let mut buf = [0u8; 14];
        write_header((&mut buf[..4]).try_into().unwrap(), true, 14);
        write_control_extra(
            (&mut buf[4..8]).try_into().unwrap(),
            MessageType::CallConnectRequest,
            1,
        );
        write_attr_header(
            (&mut buf[8..12]).try_into().unwrap(),
            AttributeId::EncapsulatedProtocolId,
            6,
        );
        buf[12..14].copy_from_slice(&SSTP_ENCAPSULATED_PROTOCOL_PPP.to_be_bytes());
        match parse_one(&buf) {
            ControlMessage::CallConnectRequest { protocol_id } => {
                assert_eq!(protocol_id, SSTP_ENCAPSULATED_PROTOCOL_PPP);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn encode_then_parse_call_connect_ack() {
        let nonce = [0xa5u8; 32];
        let mut buf = [0u8; CALL_CONNECT_ACK_LEN];
        let n = encode_call_connect_ack(&mut buf, CERT_HASH_PROTOCOL_SHA256, &nonce);
        assert_eq!(n, CALL_CONNECT_ACK_LEN);
        let (Packet::Control(c), used) = Packet::parse(&buf).unwrap() else {
            panic!()
        };
        assert_eq!(used, CALL_CONNECT_ACK_LEN);
        assert_eq!(c.msg_type, MessageType::CallConnectAck);
        assert_eq!(c.num_attrs, 1);
        let req = AttrIter::new(c.attrs)
            .next()
            .unwrap()
            .unwrap()
            .as_crypto_binding_req()
            .unwrap();
        assert_eq!(req.hash_bitmask, CERT_HASH_PROTOCOL_SHA256);
        assert_eq!(req.nonce, nonce);
    }

    #[test]
    fn encode_call_connect_nak_roundtrip() {
        let mut buf = [0u8; 32];
        let n = encode_call_connect_nak(
            &mut buf,
            AttributeId::EncapsulatedProtocolId.as_u8(),
            StatusCode::ValueNotSupported,
        );
        assert_eq!(n, 20);
        let (Packet::Control(c), _) = Packet::parse(&buf[..n]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallConnectNak);
        assert_eq!(c.num_attrs, 1);
        let info = AttrIter::new(c.attrs)
            .next()
            .unwrap()
            .unwrap()
            .as_status_info()
            .unwrap();
        assert_eq!(info.attrib_id, AttributeId::EncapsulatedProtocolId.as_u8());
        assert_eq!(info.status, StatusCode::ValueNotSupported as u32);
    }

    #[test]
    fn encode_empty_messages() {
        for ty in [
            MessageType::CallDisconnectAck,
            MessageType::EchoRequest,
            MessageType::EchoResponse,
        ] {
            let mut buf = [0u8; 8];
            let n = encode_empty_control(&mut buf, ty);
            assert_eq!(n, EMPTY_CONTROL_LEN);
            let (Packet::Control(c), _) = Packet::parse(&buf).unwrap() else {
                panic!()
            };
            assert_eq!(c.msg_type, ty);
            assert_eq!(c.num_attrs, 0);
        }
    }

    #[test]
    fn encode_disconnect_with_and_without_status() {
        let mut buf = [0u8; 32];
        assert_eq!(encode_call_disconnect(&mut buf, false), 8);
        let n = encode_call_disconnect(&mut buf, true);
        assert_eq!(n, 20);
        let (Packet::Control(c), _) = Packet::parse(&buf[..n]).unwrap() else {
            panic!()
        };
        assert_eq!(c.msg_type, MessageType::CallDisconnect);
        let info = AttrIter::new(c.attrs)
            .next()
            .unwrap()
            .unwrap()
            .as_status_info()
            .unwrap();
        assert_eq!(info.attrib_id, AttributeId::NoError.as_u8());
        assert_eq!(info.status, 0);
    }

    #[test]
    fn encode_call_connected_pre_mac_layout() {
        let nonce = [0x5au8; 32];
        let cert_hash = [0x11u8; 20];
        let mut buf = [0u8; CALL_CONNECTED_LEN];
        encode_call_connected_pre_mac(&mut buf, attr::CERT_HASH_PROTOCOL_SHA1, &nonce, &cert_hash);
        let (Packet::Control(c), used) = Packet::parse(&buf).unwrap() else {
            panic!()
        };
        assert_eq!(used, CALL_CONNECTED_LEN);
        assert_eq!(c.msg_type, MessageType::CallConnected);
        let cb = AttrIter::new(c.attrs)
            .next()
            .unwrap()
            .unwrap()
            .as_crypto_binding()
            .unwrap();
        assert_eq!(cb.hash_protocol, attr::CERT_HASH_PROTOCOL_SHA1);
        assert_eq!(cb.nonce, nonce);
        assert_eq!(&cb.cert_hash_block[..20], &cert_hash);
        assert!(cb.cert_hash_block[20..].iter().all(|&b| b == 0));
        assert!(cb.compound_mac_block.iter().all(|&b| b == 0));

        let mac = [0x42u8; 20];
        install_compound_mac(&mut buf, &mac);
        assert_eq!(&buf[80..100], &mac);
        assert!(buf[100..112].iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_call_connect_request_with_extra_attr() {
        let mut buf = [0u8; 20];
        write_header((&mut buf[..4]).try_into().unwrap(), true, 20);
        write_control_extra(
            (&mut buf[4..8]).try_into().unwrap(),
            MessageType::CallConnectRequest,
            2,
        );
        write_attr_header(
            (&mut buf[8..12]).try_into().unwrap(),
            AttributeId::EncapsulatedProtocolId,
            6,
        );
        buf[12..14].copy_from_slice(&1u16.to_be_bytes());
        write_attr_header(
            (&mut buf[14..18]).try_into().unwrap(),
            AttributeId::EncapsulatedProtocolId,
            6,
        );
        buf[18..20].copy_from_slice(&1u16.to_be_bytes());
        let (Packet::Control(c), _) = Packet::parse(&buf).unwrap() else {
            panic!()
        };
        assert!(parse_control(c).is_err());
    }
}
