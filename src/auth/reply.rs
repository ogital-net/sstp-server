//! Project a RADIUS reply's attribute bytes into our typed
//! [`AuthAccept`] / failure model.
//!
//! The upstream [`radius_tokio::client::RadiusClient`] returns an
//! [`AccessOutcome`](radius_tokio::client::AccessOutcome) carrying
//! the reply's `attributes` slice plus the Request Authenticator that
//! was sent. That's everything this module needs — the Response
//! Authenticator + Message-Authenticator have already been verified
//! by the client.

use radius_tokio::dict::{microsoft, rfc};

use crate::auth::{AuthAccept, AuthError};

/// Decode an Access-Accept's attribute list.
///
/// `request_authenticator` is the RA from the *outbound*
/// Access-Request, needed to decrypt `MS-MPPE-{Send,Recv}-Key`.
pub fn decode_accept(
    attrs: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<AuthAccept, AuthError> {
    let framed_ip = radius_tokio::attributes::first(attrs, rfc::attrs::FRAMED_IP_ADDRESS)
        .ok_or(AuthError::MissingAttribute("Framed-IP-Address"))?;

    let framed_netmask = radius_tokio::attributes::first(attrs, rfc::attrs::FRAMED_IP_NETMASK);
    let framed_mtu = radius_tokio::attributes::first(attrs, rfc::attrs::FRAMED_MTU);

    let primary_dns =
        radius_tokio::attributes::first_vsa(attrs, microsoft::attrs::MS_PRIMARY_DNS_SERVER);
    let secondary_dns =
        radius_tokio::attributes::first_vsa(attrs, microsoft::attrs::MS_SECONDARY_DNS_SERVER);
    let primary_nbns =
        radius_tokio::attributes::first_vsa(attrs, microsoft::attrs::MS_PRIMARY_NBNS_SERVER);
    let secondary_nbns =
        radius_tokio::attributes::first_vsa(attrs, microsoft::attrs::MS_SECONDARY_NBNS_SERVER);

    let mppe_send_key = mppe_key(
        attrs,
        secret,
        request_authenticator,
        microsoft::attrs::MS_MPPE_SEND_KEY,
    )?;
    let mppe_recv_key = mppe_key(
        attrs,
        secret,
        request_authenticator,
        microsoft::attrs::MS_MPPE_RECV_KEY,
    )?;

    Ok(AuthAccept {
        framed_ip,
        framed_netmask,
        framed_mtu,
        primary_dns,
        secondary_dns,
        primary_nbns,
        secondary_nbns,
        mppe_send_key,
        mppe_recv_key,
    })
}

/// `Reply-Message` (RFC 2865 §5.18) from an Access-Reject, if any.
#[must_use]
pub fn reject_reason(attrs: &[u8]) -> Option<String> {
    radius_tokio::attributes::first(attrs, rfc::attrs::REPLY_MESSAGE).map(str::to_owned)
}

fn mppe_key(
    attrs: &[u8],
    secret: &[u8],
    ra: &[u8; 16],
    handle: radius_tokio::typed::VsaAttr<radius_tokio::typed::WBytes>,
) -> Result<Vec<u8>, AuthError> {
    let Some(raw) = radius_tokio::attributes::first_vsa(attrs, handle) else {
        return Ok(Vec::new());
    };
    radius_tokio::mppe::mppe_key_decrypt(raw, secret, ra)
        .map(|k| k.to_vec())
        .map_err(|_| AuthError::Malformed("MPPE key decrypt failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_tokio::{Code, Reply};
    use std::net::Ipv4Addr;

    #[test]
    fn accept_round_trip() {
        let secret = b"shh";
        let auth = [0x5A; 16];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 42);
        reply
            .add(rfc::attrs::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 1, 2, 3))
            .unwrap();
        reply
            .add_vsa(
                microsoft::attrs::MS_PRIMARY_DNS_SERVER,
                Ipv4Addr::new(10, 0, 0, 53),
            )
            .unwrap();
        let sealed = reply.seal_for(&auth, secret);

        // Slice past the 20-byte header to mirror what `AccessOutcome`
        // hands us.
        let attrs = &sealed.as_bytes()[20..];
        let acc = decode_accept(attrs, secret, &auth).unwrap();
        assert_eq!(acc.framed_ip, Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(acc.primary_dns, Some(Ipv4Addr::new(10, 0, 0, 53)));
        assert!(acc.mppe_send_key.is_empty());
        assert!(acc.mppe_recv_key.is_empty());
    }

    #[test]
    fn reject_carries_reply_message() {
        let secret = b"shh";
        let auth = [0x33; 16];
        let mut reply = Reply::new(Code::ACCESS_REJECT, 9);
        reply.add(rfc::attrs::REPLY_MESSAGE, "no").unwrap();
        let sealed = reply.seal_for(&auth, secret);
        let attrs = &sealed.as_bytes()[20..];
        assert_eq!(reject_reason(attrs).as_deref(), Some("no"));
    }

    #[test]
    fn missing_framed_ip_rejected() {
        let secret = b"shh";
        let auth = [0xCC; 16];
        let reply = Reply::new(Code::ACCESS_ACCEPT, 1);
        let sealed = reply.seal_for(&auth, secret);
        let attrs = &sealed.as_bytes()[20..];
        let err = decode_accept(attrs, secret, &auth).unwrap_err();
        assert!(matches!(err, AuthError::MissingAttribute("Framed-IP-Address")));
    }
}
