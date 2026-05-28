//! IP Control Protocol ([RFC 1332]) packet and option codecs, plus the
//! Microsoft DNS/NBNS extensions from [RFC 1877].
//!
//! IPCP shares its packet envelope with LCP ([RFC 1661] §5) — Code (1),
//! Identifier (1), Length (2), then a sequence of Type-Length-Value
//! options. We reuse [`super::lcp`]'s packet decoder and only spell out
//! the IPCP-specific code and option types here. Driving the IPCP
//! conversation is left to [`super::fsm::Fsm`].

use thiserror::Error;

/// IPCP Code field values ([RFC 1332] §3.2). Configure-Request through
/// Code-Reject share LCP's encoding ([RFC 1661] §5) and reuse the same
/// numeric values 1-7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcpCode {
    ConfigureRequest = 1,
    ConfigureAck = 2,
    ConfigureNak = 3,
    ConfigureReject = 4,
    TerminateRequest = 5,
    TerminateAck = 6,
    CodeReject = 7,
}

impl IpcpCode {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::ConfigureRequest,
            2 => Self::ConfigureAck,
            3 => Self::ConfigureNak,
            4 => Self::ConfigureReject,
            5 => Self::TerminateRequest,
            6 => Self::TerminateAck,
            7 => Self::CodeReject,
            _ => return None,
        })
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// IPCP Configuration Option types.
///
/// 1-4 are from [RFC 1332] §3.3 + §3.4 (with the historical IP-Addresses
/// option intentionally absent — it is deprecated and Windows clients
/// never request it). 129-132 are the Microsoft DNS/NBNS extensions
/// from [RFC 1877] which Windows SSTP clients always include.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcpOptionId {
    /// `IP-Compression-Protocol` ([RFC 1332] §3.2). We always reject;
    /// Van Jacobson header compression has no value over TLS.
    IpCompressionProtocol = 2,
    /// `IP-Address` ([RFC 1332] §3.3). The single attribute every IPCP
    /// negotiation centres on.
    IpAddress = 3,
    /// `Mobile-IPv4` ([RFC 2290] §3.2) — we always reject.
    MobileIpv4 = 4,
    /// `Primary-DNS-Address` ([RFC 1877] §1.1).
    PrimaryDns = 129,
    /// `Primary-NBNS-Address` ([RFC 1877] §1.2).
    PrimaryNbns = 130,
    /// `Secondary-DNS-Address` ([RFC 1877] §1.3).
    SecondaryDns = 131,
    /// `Secondary-NBNS-Address` ([RFC 1877] §1.4).
    SecondaryNbns = 132,
}

impl IpcpOptionId {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            2 => Self::IpCompressionProtocol,
            3 => Self::IpAddress,
            4 => Self::MobileIpv4,
            129 => Self::PrimaryDns,
            130 => Self::PrimaryNbns,
            131 => Self::SecondaryDns,
            132 => Self::SecondaryNbns,
            _ => return None,
        })
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Decoder errors for IPCP option payloads.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpcpError {
    #[error("option value has wrong length: expected {expected}, got {actual}")]
    BadOptionLength { expected: usize, actual: usize },
}

/// Length of an IPv4-address-bearing option value: 4 bytes ([RFC 1332]
/// §3.3, [RFC 1877] §1.1-1.4).
pub const IPV4_OPTION_VALUE_LEN: usize = 4;
/// Full on-wire size of an IPv4-address-bearing option (header + value).
pub const IPV4_OPTION_TOTAL_LEN: usize = 2 + IPV4_OPTION_VALUE_LEN;

/// Helper: read an IPv4 address from an option value (4 bytes, network
/// byte order).
pub fn read_ipv4_value(value: &[u8]) -> Result<[u8; 4], IpcpError> {
    if value.len() != IPV4_OPTION_VALUE_LEN {
        return Err(IpcpError::BadOptionLength {
            expected: IPV4_OPTION_VALUE_LEN,
            actual: value.len(),
        });
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(value);
    Ok(out)
}

/// Encode an IPv4-bearing IPCP option (type + length + 4-byte address)
/// into `out`. Returns the number of bytes written.
pub fn write_ipv4_option(out: &mut [u8], option_type: u8, addr: [u8; 4]) -> usize {
    assert!(
        out.len() >= IPV4_OPTION_TOTAL_LEN,
        "IPCP option encode buffer too small"
    );
    out[0] = option_type;
    #[allow(clippy::cast_possible_truncation)]
    {
        out[1] = IPV4_OPTION_TOTAL_LEN as u8;
    }
    out[2..IPV4_OPTION_TOTAL_LEN].copy_from_slice(&addr);
    IPV4_OPTION_TOTAL_LEN
}

// --- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppp::lcp::{ConfigOptionIter, decode_lcp_packet};

    #[test]
    fn code_round_trip() {
        for c in [
            IpcpCode::ConfigureRequest,
            IpcpCode::ConfigureAck,
            IpcpCode::ConfigureNak,
            IpcpCode::ConfigureReject,
            IpcpCode::TerminateRequest,
            IpcpCode::TerminateAck,
            IpcpCode::CodeReject,
        ] {
            assert_eq!(IpcpCode::from_u8(c.as_u8()), Some(c));
        }
        assert_eq!(IpcpCode::from_u8(0), None);
        assert_eq!(IpcpCode::from_u8(8), None);
    }

    #[test]
    fn option_id_round_trip() {
        for o in [
            IpcpOptionId::IpAddress,
            IpcpOptionId::PrimaryDns,
            IpcpOptionId::PrimaryNbns,
            IpcpOptionId::SecondaryDns,
            IpcpOptionId::SecondaryNbns,
        ] {
            assert_eq!(IpcpOptionId::from_u8(o.as_u8()), Some(o));
        }
        assert_eq!(IpcpOptionId::from_u8(0), None);
        assert_eq!(IpcpOptionId::from_u8(5), None);
    }

    #[test]
    fn ipv4_option_round_trip() {
        let mut buf = [0u8; 8];
        let n = write_ipv4_option(&mut buf, IpcpOptionId::IpAddress.as_u8(), [10, 0, 0, 7]);
        assert_eq!(n, IPV4_OPTION_TOTAL_LEN);
        assert_eq!(buf[0], IpcpOptionId::IpAddress.as_u8());
        assert_eq!(buf[1], u8::try_from(IPV4_OPTION_TOTAL_LEN).unwrap());
        assert_eq!(read_ipv4_value(&buf[2..6]).unwrap(), [10, 0, 0, 7]);
    }

    #[test]
    fn read_ipv4_rejects_wrong_length() {
        assert!(matches!(
            read_ipv4_value(&[1, 2, 3]),
            Err(IpcpError::BadOptionLength { .. })
        ));
    }

    #[test]
    fn decode_typical_windows_configure_request() {
        // Code=1 (Configure-Request), Id=1, Len=22:
        //   IP-Address(3) len=6 0.0.0.0
        //   Primary-DNS(129) len=6 0.0.0.0
        //   Secondary-DNS(131) len=6 0.0.0.0
        let buf = [
            0x01, 0x01, 0x00, 0x16,
            0x03, 0x06, 0x00, 0x00, 0x00, 0x00,
            0x81, 0x06, 0x00, 0x00, 0x00, 0x00,
            0x83, 0x06, 0x00, 0x00, 0x00, 0x00,
        ];
        let packet = decode_lcp_packet(&buf).unwrap();
        assert_eq!(packet.code, IpcpCode::ConfigureRequest.as_u8());
        assert_eq!(packet.identifier, 1);

        let mut iter = ConfigOptionIter::new(packet.data);
        let opts: Vec<_> = (&mut iter).collect::<Result<_, _>>().unwrap();
        assert_eq!(opts.len(), 3);

        let typed: Vec<_> = opts.iter().map(|o| IpcpOptionId::from_u8(o.option_type)).collect();
        assert_eq!(
            typed,
            vec![
                Some(IpcpOptionId::IpAddress),
                Some(IpcpOptionId::PrimaryDns),
                Some(IpcpOptionId::SecondaryDns),
            ]
        );
        for o in &opts {
            assert_eq!(read_ipv4_value(o.value).unwrap(), [0, 0, 0, 0]);
        }
    }
}
