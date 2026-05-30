//! Crypto Binding verification ([MS-SSTP] §3.2.5.2, §3.3.5.2.3).
//!
//! Server-side validation of the Crypto Binding attribute received in a
//! Call Connected message: structural checks against the cached
//! Crypto Binding Request state, then a constant-time check of the
//! Compound MAC computed as `HMAC(CMK, packet-with-zeroed-mac)` where
//! `CMK = PRF+(HLAK, "SSTP inner method derived CMK", N)`.

use super::attr::{CERT_HASH_PROTOCOL_SHA1, CERT_HASH_PROTOCOL_SHA256, CryptoBinding};
use crate::crypto::{
    const_time_eq,
    hmac::{HmacSha1, HmacSha256, prf_plus_sha1_cmk, prf_plus_sha256_cmk},
};

/// CMK seed string ([MS-SSTP] §3.2.5.2.2 / §3.2.5.2.4).
pub const CMK_SEED: &[u8; 29] = b"SSTP inner method derived CMK";

/// Outcome of validating an incoming Crypto Binding attribute. The
/// state machine maps each variant to a specific Call Abort
/// `Status-Info` payload per [MS-SSTP] §3.3.5.2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingOutcome {
    Ok,
    /// Attribute missing / wrong length / Status-Info with status != `NO_ERROR`.
    #[allow(dead_code)] // FUTURE: produced once Call-Connected attribute validation rejects malformed inputs (today the verify path only flags MAC mismatch as `ValueNotSupported`).
    AttribNotSupportedInMsg,
    /// Nonce mismatch, cert hash mismatch, unsupported hash algorithm,
    /// or invalid Compound MAC.
    ValueNotSupported,
}

/// Inputs the server tracks for a single in-flight Call Connect
/// exchange ([MS-SSTP] §3.3.1 ADM variables).
#[derive(Debug, Clone)]
pub struct ServerBindingState {
    /// Nonce the server sent in its Call Connect Ack.
    pub server_nonce: [u8; 32],
    /// SHA1 (20) or SHA256 (32) hash of the server certificate.
    pub server_cert_hash: Vec<u8>,
    /// Bitmask of hash protocols the server advertised.
    pub server_hash_protocol_supported: u8,
    /// Higher-Layer Authentication Key handed up by PPP, or `None`
    /// when higher-layer auth was bypassed (`ServerBypassHLAuth` = TRUE,
    /// HLAK = zero per §3.3.7.1).
    pub hlak: Option<[u8; 32]>,
}

/// Validate a received Crypto Binding attribute against the server's
/// expected state, including a constant-time Compound MAC check.
///
/// `received_packet_with_zeroed_mac` is the full 112-byte Call
/// Connected message with the Compound MAC field (and its padding)
/// zeroed, per §3.2.5.2.1 / §3.2.5.2.3.
pub fn verify(
    binding: &CryptoBinding<'_>,
    state: &ServerBindingState,
    received_packet_with_zeroed_mac: &[u8],
) -> BindingOutcome {
    // Hash protocol must be one the server advertised.
    let (proto_bit, hash_len) = match binding.hash_protocol {
        CERT_HASH_PROTOCOL_SHA1 => (CERT_HASH_PROTOCOL_SHA1, 20usize),
        CERT_HASH_PROTOCOL_SHA256 => (CERT_HASH_PROTOCOL_SHA256, 32usize),
        _ => return BindingOutcome::ValueNotSupported,
    };
    if state.server_hash_protocol_supported & proto_bit == 0 {
        return BindingOutcome::ValueNotSupported;
    }
    if binding.nonce != state.server_nonce {
        return BindingOutcome::ValueNotSupported;
    }
    if state.server_cert_hash.len() != hash_len
        || !const_time_eq(
            &binding.cert_hash_block[..hash_len],
            state.server_cert_hash.as_slice(),
        )
    {
        return BindingOutcome::ValueNotSupported;
    }

    // HLAK defaults to 32 zero octets when higher-layer auth was
    // bypassed (§3.2.5.2.2 / §3.2.5.2.4 "ServerBypassHLAuth").
    let hlak = state.hlak.unwrap_or([0u8; 32]);

    let mac_ok = match binding.hash_protocol {
        CERT_HASH_PROTOCOL_SHA1 => {
            let cmk = prf_plus_sha1_cmk(&hlak, CMK_SEED);
            let computed = HmacSha1::oneshot(&cmk, received_packet_with_zeroed_mac);
            const_time_eq(&computed, &binding.compound_mac_block[..20])
        }
        CERT_HASH_PROTOCOL_SHA256 => {
            let cmk = prf_plus_sha256_cmk(&hlak, CMK_SEED);
            let computed = HmacSha256::oneshot(&cmk, received_packet_with_zeroed_mac);
            const_time_eq(&computed, &binding.compound_mac_block[..32])
        }
        _ => unreachable!("filtered above"),
    };

    if mac_ok {
        BindingOutcome::Ok
    } else {
        BindingOutcome::ValueNotSupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sstp::attr::CryptoBinding;

    fn make_state(nonce: [u8; 32], hash: &[u8], advertised: u8) -> ServerBindingState {
        ServerBindingState {
            server_nonce: nonce,
            server_cert_hash: hash.to_vec(),
            server_hash_protocol_supported: advertised,
            hlak: Some([0u8; 32]),
        }
    }

    fn make_binding<'a>(
        hash_proto: u8,
        nonce: [u8; 32],
        cert_hash: &[u8],
        cert_buf: &'a mut [u8; 32],
        mac_buf: &'a mut [u8; 32],
    ) -> CryptoBinding<'a> {
        cert_buf[..cert_hash.len()].copy_from_slice(cert_hash);
        CryptoBinding {
            hash_protocol: hash_proto,
            nonce,
            cert_hash_block: cert_buf,
            compound_mac_block: mac_buf,
        }
    }

    fn expected_mac_sha256(hlak: &[u8; 32], packet: &[u8]) -> [u8; 32] {
        let cmk = prf_plus_sha256_cmk(hlak, CMK_SEED);
        HmacSha256::oneshot(&cmk, packet)
    }

    fn expected_mac_sha1(hlak: &[u8; 32], packet: &[u8]) -> [u8; 20] {
        let cmk = prf_plus_sha1_cmk(hlak, CMK_SEED);
        HmacSha1::oneshot(&cmk, packet)
    }

    #[test]
    fn accepts_matching_sha256_with_correct_mac() {
        let nonce = [0xaa; 32];
        let cert = [0x11u8; 32];
        let state = make_state(nonce, &cert, CERT_HASH_PROTOCOL_SHA256);
        let packet = [0u8; 112];
        let mac = expected_mac_sha256(&state.hlak.unwrap(), &packet);

        let mut cb_buf = [0u8; 32];
        let mut mac_buf = [0u8; 32];
        mac_buf.copy_from_slice(&mac);
        let cb = make_binding(
            CERT_HASH_PROTOCOL_SHA256,
            nonce,
            &cert,
            &mut cb_buf,
            &mut mac_buf,
        );
        assert_eq!(verify(&cb, &state, &packet), BindingOutcome::Ok);
    }

    #[test]
    fn accepts_matching_sha1_with_correct_mac() {
        let nonce = [0xaa; 32];
        let cert = [0x22u8; 20];
        let state = make_state(nonce, &cert, CERT_HASH_PROTOCOL_SHA1);
        let packet = [0xffu8; 112];
        let mac = expected_mac_sha1(&state.hlak.unwrap(), &packet);

        let mut cb_buf = [0u8; 32];
        let mut mac_buf = [0u8; 32];
        mac_buf[..20].copy_from_slice(&mac);
        let cb = make_binding(
            CERT_HASH_PROTOCOL_SHA1,
            nonce,
            &cert,
            &mut cb_buf,
            &mut mac_buf,
        );
        assert_eq!(verify(&cb, &state, &packet), BindingOutcome::Ok);
    }

    #[test]
    fn rejects_bad_mac() {
        let nonce = [0xaa; 32];
        let cert = [0x11u8; 32];
        let state = make_state(nonce, &cert, CERT_HASH_PROTOCOL_SHA256);
        let packet = [0u8; 112];

        let mut cb_buf = [0u8; 32];
        let mut mac_buf = [0u8; 32]; // all zeros — wrong MAC
        let cb = make_binding(
            CERT_HASH_PROTOCOL_SHA256,
            nonce,
            &cert,
            &mut cb_buf,
            &mut mac_buf,
        );
        assert_eq!(
            verify(&cb, &state, &packet),
            BindingOutcome::ValueNotSupported
        );
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let cert = [0x11u8; 32];
        let state = make_state([0xaa; 32], &cert, CERT_HASH_PROTOCOL_SHA256);
        let mut cb_buf = [0u8; 32];
        let mut mac_buf = [0u8; 32];
        let cb = make_binding(
            CERT_HASH_PROTOCOL_SHA256,
            [0xbb; 32],
            &cert,
            &mut cb_buf,
            &mut mac_buf,
        );
        assert_eq!(verify(&cb, &state, &[]), BindingOutcome::ValueNotSupported);
    }

    #[test]
    fn rejects_unsupported_hash_protocol() {
        let cert = [0x11u8; 20];
        let state = make_state([0xaa; 32], &cert, CERT_HASH_PROTOCOL_SHA256);
        let mut cb_buf = [0u8; 32];
        let mut mac_buf = [0u8; 32];
        let cb = make_binding(
            CERT_HASH_PROTOCOL_SHA1,
            [0xaa; 32],
            &cert,
            &mut cb_buf,
            &mut mac_buf,
        );
        // Server only advertised SHA256.
        assert_eq!(verify(&cb, &state, &[]), BindingOutcome::ValueNotSupported);
    }

    #[test]
    fn rejects_cert_hash_mismatch() {
        let nonce = [0xaa; 32];
        let state = make_state(nonce, &[0x11u8; 32], CERT_HASH_PROTOCOL_SHA256);
        let mut cb_buf = [0u8; 32];
        let mut mac_buf = [0u8; 32];
        let bad = [0x22u8; 32];
        let cb = make_binding(
            CERT_HASH_PROTOCOL_SHA256,
            nonce,
            &bad,
            &mut cb_buf,
            &mut mac_buf,
        );
        assert_eq!(verify(&cb, &state, &[]), BindingOutcome::ValueNotSupported);
    }
}
