//! SSTP attribute TLV encoding/decoding ([MS-SSTP] §2.2.4–2.2.8).
//!
//! Wire layout (network byte order):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Reserved    | Attribute ID  |   R   |        Length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Value (variable) ...                      |
//! ```
//! `Length` is 12 bits and includes the 4-byte attribute header.

// Full SSTP attribute set. `StatusInfo` and several `AttributeId`
// variants / accessor methods are decoded but not yet acted on by
// the state machine (they fire on abort paths the server doesn't
// originate today). Kept ready for spec-complete client interop.
#![allow(dead_code)]

use super::frame::ParseError;

pub const ATTR_HEADER_LEN: usize = 4;

/// Attribute identifier ([MS-SSTP] §2.2.4 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttributeId {
    /// Reserved "no error" marker used inside `Status-Info` only.
    NoError = 0x00,
    EncapsulatedProtocolId = 0x01,
    StatusInfo = 0x02,
    CryptoBinding = 0x03,
    CryptoBindingReq = 0x04,
}

impl AttributeId {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x00 => Self::NoError,
            0x01 => Self::EncapsulatedProtocolId,
            0x02 => Self::StatusInfo,
            0x03 => Self::CryptoBinding,
            0x04 => Self::CryptoBindingReq,
            _ => return None,
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Hash protocol bit values used in Crypto-Binding{,-Req}
/// ([MS-SSTP] §2.2.6, §2.2.7).
pub const CERT_HASH_PROTOCOL_SHA1: u8 = 0x01;
pub const CERT_HASH_PROTOCOL_SHA256: u8 = 0x02;

/// Encapsulated protocol id value ([MS-SSTP] §2.2.5 table).
pub const SSTP_ENCAPSULATED_PROTOCOL_PPP: u16 = 0x0001;

/// `Status` field values inside Status-Info ([MS-SSTP] §2.2.8 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StatusCode {
    NoError = 0x0000_0000,
    DuplicateAttribute = 0x0000_0001,
    UnrecognizedAttribute = 0x0000_0002,
    InvalidAttribValueLength = 0x0000_0003,
    ValueNotSupported = 0x0000_0004,
    UnacceptedFrameReceived = 0x0000_0005,
    RetryCountExceeded = 0x0000_0006,
    InvalidFrameReceived = 0x0000_0007,
    NegotiationTimeout = 0x0000_0008,
    AttribNotSupportedInMsg = 0x0000_0009,
    RequiredAttributeMissing = 0x0000_000a,
    StatusInfoNotSupportedInMsg = 0x0000_000b,
}

/// Raw attribute view borrowing into the source packet.
#[derive(Debug, Clone, Copy)]
pub struct Attribute<'a> {
    pub id: AttributeId,
    /// Attribute value (the TLV's `Value` field, header stripped).
    pub value: &'a [u8],
}

impl<'a> Attribute<'a> {
    /// Decode this attribute as an Encapsulated-Protocol-Id
    /// ([MS-SSTP] §2.2.5). Returns the 16-bit protocol id.
    pub fn as_encapsulated_protocol(&self) -> Result<u16, ParseError> {
        if self.id != AttributeId::EncapsulatedProtocolId {
            return Err(ParseError::UnknownAttributeId(self.id.as_u8()));
        }
        if self.value.len() != 2 {
            return Err(ParseError::AttributeSize {
                actual: self.value.len(),
                expected: 2,
            });
        }
        Ok(u16::from_be_bytes([self.value[0], self.value[1]]))
    }

    /// Decode as a Crypto-Binding-Req ([MS-SSTP] §2.2.6).
    pub fn as_crypto_binding_req(&self) -> Result<CryptoBindingReq, ParseError> {
        if self.id != AttributeId::CryptoBindingReq {
            return Err(ParseError::UnknownAttributeId(self.id.as_u8()));
        }
        // Length field is fixed at 40 (includes 4-byte header) per spec.
        if self.value.len() != CryptoBindingReq::VALUE_LEN {
            return Err(ParseError::AttributeSize {
                actual: self.value.len(),
                expected: CryptoBindingReq::VALUE_LEN,
            });
        }
        // 3-byte Reserved1 then 1-byte Hash Protocol Bitmask then 32-byte Nonce.
        let hash_bitmask = self.value[3];
        let nonce = self.value[4..36].try_into().expect("len checked above");
        Ok(CryptoBindingReq {
            hash_bitmask,
            nonce,
        })
    }

    /// Decode as a Crypto-Binding ([MS-SSTP] §2.2.7).
    pub fn as_crypto_binding(&self) -> Result<CryptoBinding<'a>, ParseError> {
        if self.id != AttributeId::CryptoBinding {
            return Err(ParseError::UnknownAttributeId(self.id.as_u8()));
        }
        // Length is fixed at 104 (4 header + 100 value).
        if self.value.len() != CryptoBinding::VALUE_LEN {
            return Err(ParseError::AttributeSize {
                actual: self.value.len(),
                expected: CryptoBinding::VALUE_LEN,
            });
        }
        let hash_protocol = self.value[3];
        let nonce = self.value[4..36].try_into().expect("len checked");
        // Cert Hash + Padding occupy 32 bytes (SHA256: 32+0, SHA1: 20+12 zero pad).
        // Compound MAC + Padding1 occupy another 32 bytes.
        let cert_hash_block: &[u8; 32] = self.value[36..68].try_into().expect("len");
        let compound_mac_block: &[u8; 32] = self.value[68..100].try_into().expect("len");
        Ok(CryptoBinding {
            hash_protocol,
            nonce,
            cert_hash_block,
            compound_mac_block,
        })
    }

    /// Decode as a Status-Info ([MS-SSTP] §2.2.8). The `attrib_value`
    /// slice is at most 64 bytes per spec.
    pub fn as_status_info(&self) -> Result<StatusInfo<'a>, ParseError> {
        if self.id != AttributeId::StatusInfo {
            return Err(ParseError::UnknownAttributeId(self.id.as_u8()));
        }
        if self.value.len() < 8 {
            return Err(ParseError::AttributeSize {
                actual: self.value.len(),
                expected: 8,
            });
        }
        let attrib_id = self.value[3];
        let status =
            u32::from_be_bytes([self.value[4], self.value[5], self.value[6], self.value[7]]);
        Ok(StatusInfo {
            attrib_id,
            status,
            attrib_value: &self.value[8..],
        })
    }
}

/// Iterator over the attribute area of a control packet. Validates each
/// TLV header lazily and yields `ParseError` on malformed input.
pub struct AttrIter<'a> {
    buf: &'a [u8],
}

impl<'a> AttrIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<Attribute<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        if self.buf.len() < ATTR_HEADER_LEN {
            let err = ParseError::Truncated;
            self.buf = &[];
            return Some(Err(err));
        }
        // Reserved byte ignored.
        let id_raw = self.buf[1];
        let length = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize
            & super::frame::SSTP_MAX_PACKET_LEN;
        if length < ATTR_HEADER_LEN || length > self.buf.len() {
            let err = ParseError::AttributeLength {
                declared: length,
                available: self.buf.len(),
            };
            self.buf = &[];
            return Some(Err(err));
        }
        let Some(id) = AttributeId::from_u8(id_raw) else {
            // Skip past unknown attribute so the caller sees the error
            // but iteration could continue if it chose to.
            let err = ParseError::UnknownAttributeId(id_raw);
            self.buf = &self.buf[length..];
            return Some(Err(err));
        };
        let value = &self.buf[ATTR_HEADER_LEN..length];
        self.buf = &self.buf[length..];
        Some(Ok(Attribute { id, value }))
    }
}

/// Decoded Crypto-Binding-Req ([MS-SSTP] §2.2.6).
#[derive(Debug, Clone, Copy)]
pub struct CryptoBindingReq {
    pub hash_bitmask: u8,
    pub nonce: [u8; 32],
}

impl CryptoBindingReq {
    /// Length of the attribute *value* (excludes 4-byte TLV header).
    /// Total attribute length on the wire is 40 ([MS-SSTP] §2.2.6).
    pub const VALUE_LEN: usize = 36;
}

/// Decoded Crypto-Binding ([MS-SSTP] §2.2.7).
///
/// `cert_hash_block` is a 32-byte window covering "Cert Hash || Padding"
/// and `compound_mac_block` is the analogous 32-byte window for
/// "Compound MAC || Padding1". The active length of each is determined
/// by `hash_protocol`: 20 for SHA1 (followed by 12 zero pad bytes), 32
/// for SHA256.
#[derive(Debug, Clone, Copy)]
pub struct CryptoBinding<'a> {
    pub hash_protocol: u8,
    pub nonce: [u8; 32],
    pub cert_hash_block: &'a [u8; 32],
    pub compound_mac_block: &'a [u8; 32],
}

impl CryptoBinding<'_> {
    /// Length of the value field (excludes 4-byte TLV header). Total
    /// attribute size on the wire is 104.
    pub const VALUE_LEN: usize = 100;

    /// Active length of `cert_hash_block` / `compound_mac_block` given
    /// the negotiated hash protocol.
    pub fn hash_len(&self) -> Option<usize> {
        match self.hash_protocol {
            CERT_HASH_PROTOCOL_SHA1 => Some(20),
            CERT_HASH_PROTOCOL_SHA256 => Some(32),
            _ => None,
        }
    }
}

/// Decoded Status-Info ([MS-SSTP] §2.2.8).
#[derive(Debug, Clone, Copy)]
pub struct StatusInfo<'a> {
    pub attrib_id: u8,
    pub status: u32,
    /// At most 64 bytes per spec; empty in many cases.
    pub attrib_value: &'a [u8],
}

/// Write an attribute header into `buf[..4]`.
pub fn write_attr_header(buf: &mut [u8; ATTR_HEADER_LEN], id: AttributeId, total_len: usize) {
    debug_assert!(total_len >= ATTR_HEADER_LEN);
    debug_assert!(total_len <= super::frame::SSTP_MAX_PACKET_LEN);
    buf[0] = 0;
    buf[1] = id.as_u8();
    #[allow(clippy::cast_possible_truncation)]
    let len = (total_len as u16) & (super::frame::SSTP_MAX_PACKET_LEN as u16);
    buf[2..4].copy_from_slice(&len.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iter_encapsulated_protocol() {
        // Reserved=0, AttrId=1, Length=6, ProtocolId=PPP.
        let buf = [0x00, 0x01, 0x00, 0x06, 0x00, 0x01];
        let mut it = AttrIter::new(&buf);
        let a = it.next().unwrap().unwrap();
        assert_eq!(a.id, AttributeId::EncapsulatedProtocolId);
        assert_eq!(
            a.as_encapsulated_protocol().unwrap(),
            SSTP_ENCAPSULATED_PROTOCOL_PPP
        );
        assert!(it.next().is_none());
    }

    #[test]
    fn iter_crypto_binding_req() {
        // 40 bytes: header 4 + 3 reserved + 1 bitmask + 32 nonce.
        let mut buf = [0u8; 40];
        buf[1] = AttributeId::CryptoBindingReq.as_u8();
        buf[2] = 0x00;
        buf[3] = 40;
        buf[7] = CERT_HASH_PROTOCOL_SHA256; // hash bitmask
        for (i, b) in buf[8..40].iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let mut it = AttrIter::new(&buf);
        let req = it.next().unwrap().unwrap().as_crypto_binding_req().unwrap();
        assert_eq!(req.hash_bitmask, CERT_HASH_PROTOCOL_SHA256);
        assert_eq!(req.nonce[0], 0);
        assert_eq!(req.nonce[31], 31);
    }

    #[test]
    fn iter_crypto_binding() {
        // 104 bytes total = 4 header + 100 value.
        let mut buf = [0u8; 104];
        buf[1] = AttributeId::CryptoBinding.as_u8();
        buf[2] = 0x00;
        buf[3] = 104;
        buf[7] = CERT_HASH_PROTOCOL_SHA1;
        for (i, b) in buf[8..104].iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap();
        }
        let cb = AttrIter::new(&buf)
            .next()
            .unwrap()
            .unwrap()
            .as_crypto_binding()
            .unwrap();
        assert_eq!(cb.hash_protocol, CERT_HASH_PROTOCOL_SHA1);
        assert_eq!(cb.hash_len(), Some(20));
        assert_eq!(cb.cert_hash_block.len(), 32);
        assert_eq!(cb.compound_mac_block.len(), 32);
    }

    #[test]
    fn iter_truncated_attribute() {
        let buf = [0x00, 0x01, 0x00, 0x06, 0x00]; // length 6 but only 5 bytes
        let mut it = AttrIter::new(&buf);
        assert!(matches!(
            it.next(),
            Some(Err(ParseError::AttributeLength { .. }))
        ));
        assert!(it.next().is_none());
    }

    #[test]
    fn write_attr_header_roundtrip() {
        let mut h = [0u8; ATTR_HEADER_LEN];
        write_attr_header(&mut h, AttributeId::CryptoBindingReq, 40);
        assert_eq!(h, [0x00, 0x04, 0x00, 0x28]);
    }
}
