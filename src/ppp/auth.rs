//! PPP authentication-phase packet codecs.
//!
//! Scope is on-the-wire framing only:
//!
//! * **PAP** ([RFC 1334] §2.1) — Authenticate-Request / -Ack / -Nak.
//! * **CHAP** ([RFC 1994] §4) — Challenge / Response / Success / Failure.
//!   MS-CHAPv2 ([RFC 2759]) reuses the CHAP envelope with algorithm
//!   `0x81` and a fixed 16-byte Challenge value.
//! * **EAP** ([RFC 3748] §4) — Request / Response / Success / Failure
//!   packets carrying a 1-byte Type plus opaque Type-Data.
//!
//! Method-level logic (PAP credential check, CHAP MD5 hash, MS-CHAPv2
//! NT-hash chain, EAP-TLS / PEAP / EAP-MSCHAPv2) belongs in the RADIUS
//! bridge (`auth/` module, M4); this layer hands the raw fields off
//! and reassembles RADIUS replies into PPP packets.

use thiserror::Error;

// --- PAP ([RFC 1334] §2.1) -------------------------------------------------

pub mod pap {
    use super::Error;

    /// PAP Code field values ([RFC 1334] §2.2 table).
    #[allow(clippy::enum_variant_names)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Code {
        AuthenticateRequest = 1,
        AuthenticateAck = 2,
        AuthenticateNak = 3,
    }

    impl Code {
        #[must_use]
        pub fn from_u8(v: u8) -> Option<Self> {
            Some(match v {
                1 => Self::AuthenticateRequest,
                2 => Self::AuthenticateAck,
                3 => Self::AuthenticateNak,
                _ => return None,
            })
        }

        #[must_use]
        pub fn as_u8(self) -> u8 {
            self as u8
        }
    }

    /// Decoded Authenticate-Request ([RFC 1334] §2.2.1).
    #[derive(Debug, Clone, Copy)]
    pub struct AuthenticateRequest<'a> {
        pub identifier: u8,
        pub peer_id: &'a [u8],
        pub password: &'a [u8],
    }

    /// Common PAP header length: Code(1) + Identifier(1) + Length(2).
    pub const HEADER_LEN: usize = 4;

    /// Decode an Authenticate-Request packet body. `buf` is the entire
    /// PAP packet (including the 4-byte header).
    pub fn decode_authenticate_request(buf: &[u8]) -> Result<AuthenticateRequest<'_>, Error> {
        let (header, body) = decode_header(buf, Code::AuthenticateRequest)?;
        // Peer-ID-Length(1) + Peer-Id(N) + Passwd-Length(1) + Password(M).
        if body.is_empty() {
            return Err(Error::Truncated {
                need: 1,
                have: 0,
            });
        }
        let peer_len = body[0] as usize;
        if body.len() < 1 + peer_len + 1 {
            return Err(Error::Truncated {
                need: 1 + peer_len + 1,
                have: body.len(),
            });
        }
        let peer_id = &body[1..=peer_len];
        let pw_off = 1 + peer_len;
        let pw_len = body[pw_off] as usize;
        let pw_start = pw_off + 1;
        if body.len() < pw_start + pw_len {
            return Err(Error::Truncated {
                need: pw_start + pw_len,
                have: body.len(),
            });
        }
        Ok(AuthenticateRequest {
            identifier: header.identifier,
            peer_id,
            password: &body[pw_start..pw_start + pw_len],
        })
    }

    /// Encode an Authenticate-Ack / -Nak ([RFC 1334] §2.2.2 / §2.2.3).
    /// `message` is the user-facing message field (may be empty).
    /// Returns the number of bytes written.
    pub fn encode_response(
        out: &mut [u8],
        code: Code,
        identifier: u8,
        message: &[u8],
    ) -> usize {
        assert!(
            matches!(code, Code::AuthenticateAck | Code::AuthenticateNak),
            "PAP response must be Ack or Nak"
        );
        let msg_len = message.len();
        let total = HEADER_LEN + 1 + msg_len;
        assert!(out.len() >= total, "PAP encode buffer too small");
        assert!(
            u8::try_from(msg_len).is_ok(),
            "PAP message exceeds Msg-Length field"
        );
        assert!(
            u16::try_from(total).is_ok(),
            "PAP packet exceeds Length field"
        );

        out[0] = code.as_u8();
        out[1] = identifier;
        #[allow(clippy::cast_possible_truncation)]
        {
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[4] = msg_len as u8;
        }
        out[5..5 + msg_len].copy_from_slice(message);
        total
    }

    struct Header {
        identifier: u8,
    }

    fn decode_header(buf: &[u8], expect: Code) -> Result<(Header, &[u8]), Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let code = buf[0];
        if code != expect.as_u8() {
            return Err(Error::UnexpectedCode {
                expected: expect.as_u8(),
                actual: code,
            });
        }
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length < HEADER_LEN {
            return Err(Error::LengthTooSmall { declared: length });
        }
        if length > buf.len() {
            return Err(Error::LengthExceedsBuffer {
                declared: length,
                available: buf.len(),
            });
        }
        Ok((Header { identifier }, &buf[HEADER_LEN..length]))
    }
}

// --- CHAP ([RFC 1994] §4) -------------------------------------------------

pub mod chap {
    use super::Error;

    /// CHAP Code field values ([RFC 1994] §4.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Code {
        Challenge = 1,
        Response = 2,
        Success = 3,
        Failure = 4,
    }

    impl Code {
        #[must_use]
        pub fn from_u8(v: u8) -> Option<Self> {
            Some(match v {
                1 => Self::Challenge,
                2 => Self::Response,
                3 => Self::Success,
                4 => Self::Failure,
                _ => return None,
            })
        }

        #[must_use]
        pub fn as_u8(self) -> u8 {
            self as u8
        }
    }

    /// Algorithm identifiers carried in the CHAP LCP option ([RFC 1994]
    /// §4 reg.). Only the ones we care about are spelled out.
    pub mod algorithm {
        /// CHAP with MD5 ([RFC 1994] §4).
        pub const MD5: u8 = 0x05;
        /// MS-CHAPv1 ([RFC 2433]).
        pub const MSCHAPV1: u8 = 0x80;
        /// MS-CHAPv2 ([RFC 2759]).
        pub const MSCHAPV2: u8 = 0x81;
    }

    pub const HEADER_LEN: usize = 4;

    /// Decoded Challenge or Response packet ([RFC 1994] §4.1).
    /// `value` is the Challenge nonce (Challenge) or the response hash
    /// (Response); MS-CHAPv2 places its 49-byte response blob here.
    #[derive(Debug, Clone, Copy)]
    pub struct ChallengeResponse<'a> {
        pub identifier: u8,
        pub value: &'a [u8],
        pub name: &'a [u8],
    }

    /// Decode a Challenge or Response packet (they share the layout).
    pub fn decode_challenge_response(buf: &[u8]) -> Result<ChallengeResponse<'_>, Error> {
        let (header, body) = decode_header(buf, &[Code::Challenge.as_u8(), Code::Response.as_u8()])?;
        if body.is_empty() {
            return Err(Error::Truncated {
                need: 1,
                have: 0,
            });
        }
        let value_size = body[0] as usize;
        if body.len() < 1 + value_size {
            return Err(Error::Truncated {
                need: 1 + value_size,
                have: body.len(),
            });
        }
        let value = &body[1..=value_size];
        let name = &body[1 + value_size..];
        Ok(ChallengeResponse {
            identifier: header.identifier,
            value,
            name,
        })
    }

    /// Encode a Challenge ([RFC 1994] §4.1) or Response packet (same
    /// layout). Returns bytes written.
    pub fn encode_challenge_response(
        out: &mut [u8],
        code: Code,
        identifier: u8,
        value: &[u8],
        name: &[u8],
    ) -> usize {
        assert!(
            matches!(code, Code::Challenge | Code::Response),
            "CHAP challenge/response encoder rejects Success/Failure"
        );
        let total = HEADER_LEN + 1 + value.len() + name.len();
        assert!(out.len() >= total, "CHAP encode buffer too small");
        assert!(
            u8::try_from(value.len()).is_ok(),
            "CHAP Value-Size field overflow"
        );
        assert!(
            u16::try_from(total).is_ok(),
            "CHAP packet exceeds Length field"
        );

        out[0] = code.as_u8();
        out[1] = identifier;
        #[allow(clippy::cast_possible_truncation)]
        {
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[4] = value.len() as u8;
        }
        out[5..5 + value.len()].copy_from_slice(value);
        out[5 + value.len()..total].copy_from_slice(name);
        total
    }

    /// Encode a Success or Failure packet ([RFC 1994] §4.2 / §4.3).
    /// The message field is opaque text (e.g. MS-CHAPv2 places an
    /// `S=<authenticator>` string here).
    pub fn encode_terminal(
        out: &mut [u8],
        code: Code,
        identifier: u8,
        message: &[u8],
    ) -> usize {
        assert!(
            matches!(code, Code::Success | Code::Failure),
            "CHAP terminal encoder rejects Challenge/Response"
        );
        let total = HEADER_LEN + message.len();
        assert!(out.len() >= total, "CHAP encode buffer too small");
        assert!(
            u16::try_from(total).is_ok(),
            "CHAP packet exceeds Length field"
        );

        out[0] = code.as_u8();
        out[1] = identifier;
        #[allow(clippy::cast_possible_truncation)]
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[HEADER_LEN..total].copy_from_slice(message);
        total
    }

    struct Header {
        identifier: u8,
    }

    fn decode_header<'a>(buf: &'a [u8], accept: &[u8]) -> Result<(Header, &'a [u8]), Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let code = buf[0];
        if !accept.contains(&code) {
            return Err(Error::UnexpectedCode {
                expected: accept[0],
                actual: code,
            });
        }
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length < HEADER_LEN {
            return Err(Error::LengthTooSmall { declared: length });
        }
        if length > buf.len() {
            return Err(Error::LengthExceedsBuffer {
                declared: length,
                available: buf.len(),
            });
        }
        Ok((Header { identifier }, &buf[HEADER_LEN..length]))
    }
}

// --- EAP ([RFC 3748] §4) ---------------------------------------------------

pub mod eap {
    use super::Error;

    /// EAP Code field values ([RFC 3748] §4).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Code {
        Request = 1,
        Response = 2,
        Success = 3,
        Failure = 4,
    }

    impl Code {
        #[must_use]
        pub fn from_u8(v: u8) -> Option<Self> {
            Some(match v {
                1 => Self::Request,
                2 => Self::Response,
                3 => Self::Success,
                4 => Self::Failure,
                _ => return None,
            })
        }

        #[must_use]
        pub fn as_u8(self) -> u8 {
            self as u8
        }
    }

    /// EAP Type-Code registry — the methods we forward to RADIUS.
    /// Full IANA list at <https://www.iana.org/assignments/eap-numbers>.
    pub mod method {
        /// Identity ([RFC 3748] §5.1) — the only method we may answer
        /// in-process; everything else is opaque to the PPP layer.
        pub const IDENTITY: u8 = 1;
        /// Legacy Nak ([RFC 3748] §5.3.1).
        pub const NAK: u8 = 3;
        /// MD5-Challenge ([RFC 3748] §5.4) — not used (no MSK).
        pub const MD5_CHALLENGE: u8 = 4;
        /// EAP-TLS ([RFC 5216]).
        pub const TLS: u8 = 13;
        /// PEAP (draft-josefsson-pppext-eap-tls-eap-10).
        pub const PEAP: u8 = 25;
        /// EAP-MSCHAPv2 ([RFC 2759] + draft-kamath-pppext-eap-mschapv2).
        pub const MSCHAPV2: u8 = 26;
        /// EAP-TTLS ([RFC 5281]).
        pub const TTLS: u8 = 21;
    }

    /// Header length: Code(1) + Identifier(1) + Length(2).
    pub const HEADER_LEN: usize = 4;
    /// Header length for Request/Response (header + Type byte).
    pub const REQ_RESP_HEADER_LEN: usize = HEADER_LEN + 1;

    /// Decoded EAP packet view.
    #[derive(Debug, Clone, Copy)]
    pub struct Packet<'a> {
        pub code: u8,
        pub identifier: u8,
        /// For Request/Response, the leading byte of `payload` is the
        /// EAP Type; for Success/Failure, `payload` is empty.
        pub payload: &'a [u8],
    }

    impl Packet<'_> {
        /// Returns `(type, type_data)` for Request/Response packets.
        /// Returns `None` for Success/Failure (no Type field).
        #[must_use]
        pub fn typed(&self) -> Option<(u8, &[u8])> {
            let c = Code::from_u8(self.code)?;
            match c {
                Code::Request | Code::Response => {
                    let t = *self.payload.first()?;
                    Some((t, &self.payload[1..]))
                }
                Code::Success | Code::Failure => None,
            }
        }
    }

    /// Decode an EAP packet from a PPP information field (protocol
    /// `0xC227`). Returns a borrowed view; payload follows the 4-byte
    /// header and is bounded by the declared Length.
    pub fn decode(buf: &[u8]) -> Result<Packet<'_>, Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let code = buf[0];
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length < HEADER_LEN {
            return Err(Error::LengthTooSmall { declared: length });
        }
        if length > buf.len() {
            return Err(Error::LengthExceedsBuffer {
                declared: length,
                available: buf.len(),
            });
        }
        Ok(Packet {
            code,
            identifier,
            payload: &buf[HEADER_LEN..length],
        })
    }

    /// Encode a Request or Response packet with the given Type and
    /// Type-Data. Returns bytes written.
    pub fn encode_request_response(
        out: &mut [u8],
        code: Code,
        identifier: u8,
        type_code: u8,
        type_data: &[u8],
    ) -> usize {
        assert!(
            matches!(code, Code::Request | Code::Response),
            "EAP encode_request_response rejects Success/Failure"
        );
        let total = REQ_RESP_HEADER_LEN + type_data.len();
        assert!(out.len() >= total, "EAP encode buffer too small");
        assert!(
            u16::try_from(total).is_ok(),
            "EAP packet exceeds Length field"
        );

        out[0] = code.as_u8();
        out[1] = identifier;
        #[allow(clippy::cast_possible_truncation)]
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[4] = type_code;
        out[5..total].copy_from_slice(type_data);
        total
    }

    /// Encode an EAP Success or Failure packet ([RFC 3748] §4.2).
    /// Returns bytes written (always exactly [`HEADER_LEN`]).
    pub fn encode_terminal(out: &mut [u8], code: Code, identifier: u8) -> usize {
        assert!(
            matches!(code, Code::Success | Code::Failure),
            "EAP encode_terminal rejects Request/Response"
        );
        assert!(out.len() >= HEADER_LEN, "EAP encode buffer too small");
        out[0] = code.as_u8();
        out[1] = identifier;
        #[allow(clippy::cast_possible_truncation)]
        out[2..4].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        HEADER_LEN
    }
}

// --- Shared error type ----------------------------------------------------

/// Decoder errors shared by PAP, CHAP and EAP.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("truncated packet (need {need}, have {have})")]
    Truncated { need: usize, have: usize },
    #[error("declared Length {declared} is below header size")]
    LengthTooSmall { declared: usize },
    #[error("declared Length {declared} exceeds buffer ({available})")]
    LengthExceedsBuffer { declared: usize, available: usize },
    #[error("unexpected Code: expected {expected:#x}, got {actual:#x}")]
    UnexpectedCode { expected: u8, actual: u8 },
}

// --- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pap_decode_authenticate_request() {
        // Code=1, Id=7, Len=14, peer_len=4, peer="user", pw_len=4, pw="pass"
        let buf = [0x01, 0x07, 0x00, 0x0e, 0x04, b'u', b's', b'e', b'r', 0x04, b'p', b'a', b's', b's'];
        let r = pap::decode_authenticate_request(&buf).unwrap();
        assert_eq!(r.identifier, 7);
        assert_eq!(r.peer_id, b"user");
        assert_eq!(r.password, b"pass");
    }

    #[test]
    fn pap_round_trip_ack() {
        let mut out = [0u8; 32];
        let n = pap::encode_response(&mut out, pap::Code::AuthenticateAck, 9, b"hi");
        assert_eq!(n, 7);
        assert_eq!(&out[..n], &[0x02, 0x09, 0x00, 0x07, 0x02, b'h', b'i']);
    }

    #[test]
    fn pap_rejects_truncated_password() {
        // peer_len=4 but only 3 peer bytes present.
        let buf = [0x01, 0x01, 0x00, 0x09, 0x04, b'u', b's', b'e', 0x00];
        assert!(matches!(
            pap::decode_authenticate_request(&buf),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn chap_decode_challenge() {
        // Code=1, Id=3, Len=13, value_size=4, value=0xDEADBEEF, name="srv"
        let buf = [
            0x01, 0x03, 0x00, 0x0c, 0x04, 0xde, 0xad, 0xbe, 0xef, b's', b'r', b'v',
        ];
        let r = chap::decode_challenge_response(&buf).unwrap();
        assert_eq!(r.identifier, 3);
        assert_eq!(r.value, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(r.name, b"srv");
    }

    #[test]
    fn chap_round_trip_response() {
        let mut out = [0u8; 64];
        let n = chap::encode_challenge_response(
            &mut out,
            chap::Code::Response,
            42,
            &[0x11, 0x22, 0x33],
            b"peer",
        );
        let parsed = chap::decode_challenge_response(&out[..n]).unwrap();
        assert_eq!(parsed.identifier, 42);
        assert_eq!(parsed.value, &[0x11, 0x22, 0x33]);
        assert_eq!(parsed.name, b"peer");
    }

    #[test]
    fn chap_terminal_round_trip() {
        let mut out = [0u8; 64];
        let n = chap::encode_terminal(&mut out, chap::Code::Success, 5, b"S=AUTH");
        assert_eq!(n, 4 + 6);
        assert_eq!(&out[..4], &[0x03, 0x05, 0x00, 0x0a]);
        assert_eq!(&out[4..n], b"S=AUTH");
    }

    #[test]
    fn eap_decode_request_identity() {
        let buf = [0x01, 0x01, 0x00, 0x05, eap::method::IDENTITY];
        let p = eap::decode(&buf).unwrap();
        assert_eq!(p.code, eap::Code::Request.as_u8());
        assert_eq!(p.identifier, 1);
        let (t, td) = p.typed().unwrap();
        assert_eq!(t, eap::method::IDENTITY);
        assert!(td.is_empty());
    }

    #[test]
    fn eap_decode_success_has_no_type() {
        let buf = [0x03, 0x02, 0x00, 0x04];
        let p = eap::decode(&buf).unwrap();
        assert!(p.typed().is_none());
    }

    #[test]
    fn eap_round_trip_request() {
        let mut out = [0u8; 64];
        let n = eap::encode_request_response(
            &mut out,
            eap::Code::Request,
            17,
            eap::method::MSCHAPV2,
            &[0x01, 0x02, 0x03],
        );
        let p = eap::decode(&out[..n]).unwrap();
        assert_eq!(p.identifier, 17);
        let (t, td) = p.typed().unwrap();
        assert_eq!(t, eap::method::MSCHAPV2);
        assert_eq!(td, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn eap_rejects_length_below_header() {
        let buf = [0x01, 0x00, 0x00, 0x03, 0xff];
        assert!(matches!(
            eap::decode(&buf),
            Err(Error::LengthTooSmall { .. })
        ));
    }

    #[test]
    fn eap_rejects_length_overflow() {
        let buf = [0x01, 0x00, 0x00, 0x10, 0x01];
        assert!(matches!(
            eap::decode(&buf),
            Err(Error::LengthExceedsBuffer { .. })
        ));
    }
}
