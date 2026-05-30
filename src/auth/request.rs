//! Access-Request construction.
//!
//! Each `apply_*` helper appends the attributes describing one PPP
//! authentication exchange onto a caller-supplied [`PacketBuffer`].
//! The caller — typically [`super::client`] driving
//! [`radius_tokio::client::RadiusClient::access_request`] — owns the
//! buffer's identifier, Request Authenticator, and sealing.
//!
//! Splitting "append attributes" from "seal the packet" matches the
//! shape of `radius_tokio::client::access_request`, whose `build`
//! closure is invoked with a fresh `PacketBuffer` and the just-drawn
//! Request Authenticator.

// PAP, CHAP-MD5, and MS-CHAPv2 request builders are in active use.
// `apply_eap` (and the `MAX_ATTR_VALUE` cap shared with it) is
// scaffolding for the future EAP pass-through phase.
#![allow(dead_code)]

use radius_tokio::{
    CodecError, PacketBuffer,
    dict::{
        microsoft,
        rfc::{
            self,
            values::{FramedProtocol, ServiceType},
        },
    },
    user_password_encrypt,
};

/// SSTP runs over TLS-over-TCP — no canonical NAS-Port-Type value;
/// `Virtual` (5) is the conventional choice for L2 tunnels.
const NAS_PORT_TYPE_VIRTUAL: u32 = 5;

/// Maximum value bytes per RADIUS attribute (RFC 2865 §5).
const MAX_ATTR_VALUE: usize = 253;

/// Per-request context shared across every auth method. Holds only
/// values that go into attributes; secrets and Request Authenticators
/// belong to the [`radius_tokio::client::RadiusClient`] driving the
/// exchange.
#[derive(Debug, Clone, Copy)]
pub struct AccessRequestCtx<'a> {
    pub username: &'a str,
    pub calling_station_id: Option<&'a str>,
    pub nas_identifier: Option<&'a str>,
}

/// Append `User-Name` + framing attributes common to every method.
///
/// # Errors
///
/// Forwards `radius-tokio` [`CodecError`] on packet overflow.
pub fn apply_common(buf: &mut PacketBuffer, ctx: &AccessRequestCtx<'_>) -> Result<(), CodecError> {
    buf.add(rfc::attrs::USER_NAME, ctx.username)?;
    buf.add(rfc::attrs::NAS_PORT_TYPE, NAS_PORT_TYPE_VIRTUAL)?;
    if let Some(csid) = ctx.calling_station_id {
        buf.add(rfc::attrs::CALLING_STATION_ID, csid)?;
    }
    if let Some(nid) = ctx.nas_identifier {
        buf.add(rfc::attrs::NAS_IDENTIFIER, nid)?;
    }
    buf.add(rfc::attrs::SERVICE_TYPE, ServiceType::FRAMED_USER)?;
    buf.add(rfc::attrs::FRAMED_PROTOCOL, FramedProtocol::PPP)?;
    Ok(())
}

/// Append a PAP credential.
///
/// `User-Password` is encrypted under `secret` and `authenticator`
/// per RFC 2865 §5.2.
///
/// # Errors
///
/// Forwards [`CodecError`] on packet overflow.
pub fn apply_pap(
    buf: &mut PacketBuffer,
    ctx: &AccessRequestCtx<'_>,
    authenticator: &[u8; 16],
    secret: &[u8],
    password_cleartext: &[u8],
) -> Result<(), CodecError> {
    apply_common(buf, ctx)?;
    let ct = user_password_encrypt(password_cleartext, secret, authenticator);
    buf.add_attribute(rfc::attrs::USER_PASSWORD.code, &ct)?;
    Ok(())
}

/// Append a CHAP-MD5 credential ([RFC 1994] + RFC 2865 §5.3 / §5.40).
///
/// Validation of the response hash itself is delegated to the RADIUS
/// authenticator: we forward `CHAP-Password` (the 1-byte CHAP
/// identifier followed by the 16-byte response hash from the peer)
/// and `CHAP-Challenge` (the original 16-byte challenge we sent).
///
/// # Errors
///
/// Forwards [`CodecError`] on packet overflow.
pub fn apply_chap_md5(
    buf: &mut PacketBuffer,
    ctx: &AccessRequestCtx<'_>,
    chap_ident: u8,
    response: &[u8; 16],
    challenge: &[u8],
) -> Result<(), CodecError> {
    apply_common(buf, ctx)?;
    let mut chap_password = [0u8; 17];
    chap_password[0] = chap_ident;
    chap_password[1..].copy_from_slice(response);
    buf.add_attribute(rfc::attrs::CHAP_PASSWORD.code, &chap_password)?;
    buf.add_attribute(rfc::attrs::CHAP_CHALLENGE.code, challenge)?;
    Ok(())
}

/// Append an MS-CHAPv2 credential (RFC 2548 §2.3.2, RFC 2759).
///
/// # Errors
///
/// Forwards [`CodecError`] on packet overflow.
#[allow(clippy::too_many_arguments)]
pub fn apply_mschapv2(
    buf: &mut PacketBuffer,
    ctx: &AccessRequestCtx<'_>,
    authenticator_challenge: &[u8; 16],
    chap_ident: u8,
    peer_challenge: &[u8; 16],
    nt_response: &[u8; 24],
    flags: u8,
) -> Result<(), CodecError> {
    apply_common(buf, ctx)?;
    buf.add_vsa(
        microsoft::attrs::MS_CHAP_CHALLENGE,
        authenticator_challenge.as_slice(),
    )?;

    // MS-CHAP2-Response: Ident(1) | Flags(1) | PeerChallenge(16) |
    // Reserved(8) | NT-Response(24) = 50 bytes.
    let mut resp = [0u8; 50];
    resp[0] = chap_ident;
    resp[1] = flags;
    resp[2..18].copy_from_slice(peer_challenge);
    resp[26..50].copy_from_slice(nt_response);
    buf.add_vsa(microsoft::attrs::MS_CHAP2_RESPONSE, resp.as_slice())?;
    Ok(())
}

/// Append an EAP-Message payload (RFC 3579 §3.1), fragmenting into
/// 253-byte attribute slots as necessary. `state` is the opaque
/// `State` attribute echoed from the previous Access-Challenge, if
/// any — required after the first round-trip (RFC 2865 §5.24).
///
/// `User-Name` is included; `User-Password` is not (EAP carries its
/// own credential exchange in the EAP-Message body).
///
/// # Errors
///
/// Forwards [`CodecError`] on packet overflow.
pub fn apply_eap(
    buf: &mut PacketBuffer,
    ctx: &AccessRequestCtx<'_>,
    eap_payload: &[u8],
    state: Option<&[u8]>,
) -> Result<(), CodecError> {
    apply_common(buf, ctx)?;
    if let Some(s) = state {
        buf.add_attribute(rfc::attrs::STATE.code, s)?;
    }
    if eap_payload.is_empty() {
        buf.add_attribute(radius_tokio::eap::TYPE, &[])?;
    } else {
        for chunk in eap_payload.chunks(MAX_ATTR_VALUE) {
            buf.add_attribute(radius_tokio::eap::TYPE, chunk)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_tokio::{Code, eap, message_authenticator};

    fn ctx() -> AccessRequestCtx<'static> {
        AccessRequestCtx {
            username: "alice",
            calling_station_id: Some("198.51.100.5:443"),
            nas_identifier: Some("sstp-test"),
        }
    }

    #[test]
    fn pap_round_trip() {
        let secret = b"shh";
        let auth = [0xAA; 16];
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 7);
        apply_pap(&mut buf, &ctx(), &auth, secret, b"hunter2").unwrap();
        let sealed = buf
            .seal_as_random_authenticator_request(&auth, secret)
            .unwrap();
        let bytes = sealed.as_bytes();
        assert_eq!(bytes[0], 1, "code = Access-Request");
        assert_eq!(bytes[1], 7, "id matches");
        assert!(matches!(
            message_authenticator::verify(bytes, &auth, secret),
            message_authenticator::Verification::Valid
        ));
        let names: Vec<u8> = radius_tokio::attributes::iter(sealed.attributes())
            .filter_map(Result::ok)
            .map(|r| r.attribute_type())
            .collect();
        assert!(names.contains(&1), "User-Name");
        assert!(names.contains(&2), "User-Password");
        assert!(names.contains(&80), "Message-Authenticator");
    }

    #[test]
    fn chap_md5_emits_chap_password_and_challenge() {
        let secret = b"shh";
        let auth = [0x77; 16];
        let response = [0xAB; 16];
        let challenge = [0xCD; 16];
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 4);
        apply_chap_md5(&mut buf, &ctx(), 9, &response, &challenge).unwrap();
        let sealed = buf
            .seal_as_random_authenticator_request(&auth, secret)
            .unwrap();
        let mut saw_password = false;
        let mut saw_challenge = false;
        for raw in radius_tokio::attributes::iter(sealed.attributes()).filter_map(Result::ok) {
            match raw.attribute_type() {
                3 => {
                    saw_password = true;
                    let v = raw.value();
                    assert_eq!(v.len(), 17, "CHAP-Password is id + 16 bytes");
                    assert_eq!(v[0], 9, "chap ident byte");
                    assert_eq!(&v[1..], &response, "response hash");
                }
                60 => {
                    saw_challenge = true;
                    assert_eq!(raw.value(), &challenge);
                }
                _ => {}
            }
        }
        assert!(saw_password && saw_challenge);
    }

    #[test]
    fn mschapv2_shape() {
        let secret = b"shh";
        let auth = [0x11; 16];
        let peer = [0x22; 16];
        let nt = [0x33; 24];
        let challenge = [0x44; 16];
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 5);
        apply_mschapv2(&mut buf, &ctx(), &challenge, 9, &peer, &nt, 0).unwrap();
        let sealed = buf
            .seal_as_random_authenticator_request(&auth, secret)
            .unwrap();

        let mut saw_challenge = false;
        let mut saw_response = false;
        for raw in radius_tokio::attributes::iter(sealed.attributes()).filter_map(Result::ok) {
            if raw.attribute_type() != 26 {
                continue;
            }
            let v = raw.value();
            if v.len() < 6 || u32::from_be_bytes([v[0], v[1], v[2], v[3]]) != 311 {
                continue;
            }
            match v[4] {
                11 => {
                    saw_challenge = true;
                    assert_eq!(&v[6..], &challenge);
                }
                25 => {
                    saw_response = true;
                    assert_eq!(v[6], 9, "chap ident");
                    assert_eq!(v[7], 0, "flags");
                    assert_eq!(&v[8..24], &peer);
                    assert_eq!(&v[32..56], &nt);
                }
                _ => {}
            }
        }
        assert!(saw_challenge && saw_response);
    }

    #[test]
    fn eap_fragments_at_253_bytes() {
        let secret = b"shh";
        let auth = [0x55; 16];
        let payload: Vec<u8> = (0..600u32)
            .map(|i| u8::try_from(i & 0xff).unwrap())
            .collect();
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 3);
        apply_eap(&mut buf, &ctx(), &payload, Some(b"opaque-state")).unwrap();
        let sealed = buf
            .seal_as_random_authenticator_request(&auth, secret)
            .unwrap();

        let frags: Vec<&[u8]> = eap::fragments(sealed.attributes()).collect();
        assert_eq!(frags.len(), 3, "600B splits into 253+253+94");
        assert_eq!(frags[0].len(), 253);
        assert_eq!(frags[1].len(), 253);
        assert_eq!(frags[2].len(), 94);

        let mut reassembled = Vec::new();
        eap::reassemble_into(sealed.attributes(), &mut reassembled);
        assert_eq!(reassembled, payload);

        let state = radius_tokio::attributes::iter(sealed.attributes())
            .filter_map(Result::ok)
            .find(|r| r.attribute_type() == rfc::attrs::STATE.code)
            .expect("State present");
        assert_eq!(state.value(), b"opaque-state");
    }
}
