//! Project a RADIUS reply's attribute bytes into our typed
//! [`AuthAccept`] / failure model.
//!
//! The upstream [`radius_tokio::client::RadiusClient`] returns an
//! [`AccessOutcome`](radius_tokio::client::AccessOutcome) carrying
//! the reply's `attributes` slice plus the Request Authenticator that
//! was sent. That's everything this module needs — the Response
//! Authenticator + Message-Authenticator have already been verified
//! by the client.

use std::time::Duration;

use radius_tokio::dict::{microsoft, rfc};

use crate::auth::{AuthAccept, AuthError, FramedRoute};

/// RFC 2869 §5.16: "SHOULD NOT be more frequent than once a
/// minute". 30 s is the practical floor accel-ppp / FreeRADIUS
/// reach for; we clamp anything below that.
const MIN_ACCT_INTERIM: Duration = Duration::from_secs(30);

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
    if let Some(m) = framed_mtu {
        tracing::trace!(
            target: "sstp::mtu",
            framed_mtu = m,
            "RADIUS Access-Accept: parsed Framed-MTU (RFC 2865 §5.12)"
        );
    } else {
        tracing::trace!(
            target: "sstp::mtu",
            "RADIUS Access-Accept: no Framed-MTU; daemon default will apply"
        );
    }

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

    let shaping = mikrotik_rate_limit(attrs);

    let framed_routes = decode_framed_routes(attrs);

    // `Class` (RFC 2865 §5.25) is opaque bytes; copy verbatim. Only
    // the first instance is honoured here even though the RFC
    // allows multiple — concatenation policy is authenticator-
    // specific and we have no use case for it.
    let class = radius_tokio::attributes::first(attrs, rfc::attrs::CLASS).map(<[u8]>::to_vec);

    let session_timeout = radius_tokio::attributes::first(attrs, rfc::attrs::SESSION_TIMEOUT)
        .map(|s: u32| Duration::from_secs(u64::from(s)));
    let idle_timeout = radius_tokio::attributes::first(attrs, rfc::attrs::IDLE_TIMEOUT)
        .map(|s: u32| Duration::from_secs(u64::from(s)));
    let acct_interim_interval =
        radius_tokio::attributes::first(attrs, rfc::attrs::ACCT_INTERIM_INTERVAL).map(|s: u32| {
            let raw = Duration::from_secs(u64::from(s));
            if raw < MIN_ACCT_INTERIM {
                MIN_ACCT_INTERIM
            } else {
                raw
            }
        });

    // MS-CHAP2-Success (RFC 2548 §2.3.3) carries the
    // Authenticator-Response the peer expects to see echoed inside
    // the PPP CHAP Success packet ([RFC 2759] §6). Wire format is
    // `Ident(1) || S=<40-hex>...`; we strip the leading identifier
    // byte so the driver can splice the remainder verbatim into the
    // CHAP body.
    let mschap2_success =
        radius_tokio::attributes::first_vsa(attrs, microsoft::attrs::MS_CHAP2_SUCCESS).map(|raw| {
            if raw.is_empty() {
                Vec::new()
            } else {
                raw[1..].to_vec()
            }
        });

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
        mschap2_success,
        shaping,
        framed_routes,
        class,
        session_timeout,
        idle_timeout,
        acct_interim_interval,
    })
}

/// `Reply-Message` (RFC 2865 §5.18) from an Access-Reject, if any.
#[must_use]
pub fn reject_reason(attrs: &[u8]) -> Option<String> {
    radius_tokio::attributes::first(attrs, rfc::attrs::REPLY_MESSAGE).map(str::to_owned)
}

/// `MS-CHAP-Error` (RFC 2548 §2.1.2) from an Access-Reject, if any.
/// Wire format is `Ident(1) || "E=...R=...C=...V=...M=..."`. The
/// leading identifier byte is stripped; the remainder is the
/// payload the PPP CHAP Failure packet should carry verbatim
/// ([RFC 2759] §7).
#[must_use]
pub fn mschap_error(attrs: &[u8]) -> Option<String> {
    radius_tokio::attributes::first_vsa(attrs, microsoft::attrs::MS_CHAP_ERROR).map(|s| {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            String::new()
        } else {
            String::from_utf8_lossy(&bytes[1..]).into_owned()
        }
    })
}

/// Decode a `Mikrotik-Rate-Limit` VSA (vendor 14988, attr 8) into a
/// [`crate::shape::ShapingPolicy`], if present and parseable.
///
/// A malformed value is *not* fatal: we log it and return `None` so
/// the session still comes up unshaped — bad RADIUS dictionaries are
/// far more common than bad authenticators, and a typo in a NAS-side
/// rate string shouldn't drop every login. An empty policy (parser
/// succeeded but no rate fields were set) likewise collapses to
/// `None` so callers don't have to special-case it.
fn mikrotik_rate_limit(attrs: &[u8]) -> Option<crate::shape::ShapingPolicy> {
    use radius_tokio::typed::{VsaAttr, WText};
    let value = radius_tokio::attributes::first_vsa(attrs, VsaAttr::<WText>::new(14988, 8))?;
    match crate::shape::mikrotik::parse(value) {
        Ok(p) if !p.is_empty() => Some(p),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(
                error = %e,
                value = %value,
                "Mikrotik-Rate-Limit parse failed; ignoring shaping policy"
            );
            None
        }
    }
}

/// Decode every `Framed-Route` attribute in `attrs` (RFC 2865 §5.22).
///
/// Multiple instances are common (one per pushed route); each is
/// parsed independently. A malformed value is logged at `warn` and
/// dropped; the rest of the list survives. UTF-8 / ASCII validation
/// is enforced via `core::str::from_utf8` — RFC 2865 mandates ASCII
/// for the attribute body, so non-UTF-8 is malformed.
fn decode_framed_routes(attrs: &[u8]) -> Vec<FramedRoute> {
    let mut out = Vec::new();
    for slot in radius_tokio::attributes::iter(attrs) {
        let Ok(raw) = slot else { break };
        if raw.attribute_type() != rfc::attrs::FRAMED_ROUTE.code {
            continue;
        }
        let Ok(text) = core::str::from_utf8(raw.value()) else {
            tracing::warn!(
                len = raw.value().len(),
                "Framed-Route value is not valid UTF-8; skipping"
            );
            continue;
        };
        match FramedRoute::parse(text) {
            Ok(r) => out.push(r),
            Err(e) => {
                tracing::warn!(value = %text, error = %e, "Framed-Route parse failed; skipping");
            }
        }
    }
    out
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
        assert!(matches!(
            err,
            AuthError::MissingAttribute("Framed-IP-Address")
        ));
    }

    #[test]
    fn mikrotik_rate_limit_populates_shaping() {
        use radius_tokio::typed::{VsaAttr, WText};
        let secret = b"shh";
        let auth = [0x11; 16];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 7);
        reply
            .add(rfc::attrs::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        // Mikrotik names rates client-POV: tx=client→server (ingress on
        // server's pppN), rx=server→client (egress).
        reply
            .add_vsa(VsaAttr::<WText>::new(14988, 8), "1M/2M")
            .unwrap();
        let sealed = reply.seal_for(&auth, secret);
        let attrs = &sealed.as_bytes()[20..];
        let acc = decode_accept(attrs, secret, &auth).unwrap();
        let shaping = acc.shaping.expect("shaping populated");
        assert!(!shaping.is_empty());
        // Mikrotik format: "rx/tx" → rx is server→client (egress),
        // tx is client→server (ingress).
        assert_eq!(shaping.egress.unwrap().rate_bps, 1_000_000);
        assert_eq!(shaping.ingress.unwrap().rate_bps, 2_000_000);
    }

    #[test]
    fn mikrotik_rate_limit_garbage_yields_none() {
        use radius_tokio::typed::{VsaAttr, WText};
        let secret = b"shh";
        let auth = [0x22; 16];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 8);
        reply
            .add(rfc::attrs::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 0, 0, 2))
            .unwrap();
        reply
            .add_vsa(VsaAttr::<WText>::new(14988, 8), "not-a-rate")
            .unwrap();
        let sealed = reply.seal_for(&auth, secret);
        let attrs = &sealed.as_bytes()[20..];
        // Parse failure must not turn into a missing-Framed-IP /
        // Malformed error — the session should come up unshaped.
        let acc = decode_accept(attrs, secret, &auth).unwrap();
        assert!(acc.shaping.is_none());
    }

    // -------------------------------------------------------------
    // Additional coverage: VSA-string handling, route plumbing,
    // session/idle/interim timing, MPPE error path, reject helpers.
    // -------------------------------------------------------------

    fn build_accept(
        ident: u8,
        auth: [u8; 16],
        secret: &[u8],
        f: impl FnOnce(&mut Reply),
    ) -> Vec<u8> {
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, ident);
        reply
            .add(rfc::attrs::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        f(&mut reply);
        let sealed = reply.seal_for(&auth, secret);
        sealed.as_bytes()[20..].to_vec()
    }

    #[test]
    fn mschap2_success_strips_leading_ident_byte() {
        let secret = b"shh";
        let auth = [0xAA; 16];
        // Wire: Ident(1) || S=...
        let raw: &[u8] = b"\x07S=AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFF11";
        let attrs = build_accept(11, auth, secret, |r| {
            r.add_vsa(microsoft::attrs::MS_CHAP2_SUCCESS, raw).unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        let body = acc.mschap2_success.expect("success body present");
        assert_eq!(body, &raw[1..]);
    }

    #[test]
    fn mschap2_success_empty_yields_empty_vec() {
        let secret = b"shh";
        let auth = [0xAB; 16];
        let attrs = build_accept(12, auth, secret, |r| {
            r.add_vsa(microsoft::attrs::MS_CHAP2_SUCCESS, &[][..])
                .unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.mschap2_success, Some(Vec::new()));
    }

    #[test]
    fn mschap_error_strips_leading_ident_byte() {
        let secret = b"shh";
        let auth = [0xCC; 16];
        // mschap_error reads the *attribute bytes* including the
        // RFC 2548 §2.1.2 Ident prefix.
        let mut reply = Reply::new(Code::ACCESS_REJECT, 13);
        reply
            .add_vsa(
                microsoft::attrs::MS_CHAP_ERROR,
                "\x05E=691 R=0 V=3 M=AccessDenied",
            )
            .unwrap();
        let sealed = reply.seal_for(&auth, secret);
        let attrs = &sealed.as_bytes()[20..];
        let err = mschap_error(attrs).expect("present");
        assert_eq!(err, "E=691 R=0 V=3 M=AccessDenied");
    }

    #[test]
    fn mschap_error_absent_returns_none() {
        let secret = b"shh";
        let auth = [0xCD; 16];
        let reply = Reply::new(Code::ACCESS_REJECT, 14);
        let sealed = reply.seal_for(&auth, secret);
        assert!(mschap_error(&sealed.as_bytes()[20..]).is_none());
    }

    #[test]
    fn reject_reason_absent_returns_none() {
        let secret = b"shh";
        let auth = [0xCE; 16];
        let reply = Reply::new(Code::ACCESS_REJECT, 15);
        let sealed = reply.seal_for(&auth, secret);
        assert!(reject_reason(&sealed.as_bytes()[20..]).is_none());
    }

    #[test]
    fn framed_routes_collects_multiple_and_skips_garbage() {
        let secret = b"shh";
        let auth = [0xDE; 16];
        let attrs = build_accept(16, auth, secret, |r| {
            r.add(rfc::attrs::FRAMED_ROUTE, "192.0.2.0/24 0.0.0.0 1")
                .unwrap();
            r.add(rfc::attrs::FRAMED_ROUTE, "this is not a route")
                .unwrap();
            r.add(rfc::attrs::FRAMED_ROUTE, "198.51.100.0/24 10.0.0.1 5")
                .unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.framed_routes.len(), 2);
        assert_eq!(acc.framed_routes[0].dest, Ipv4Addr::new(192, 0, 2, 0));
        assert_eq!(acc.framed_routes[1].dest, Ipv4Addr::new(198, 51, 100, 0));
        assert_eq!(
            acc.framed_routes[1].gateway,
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn framed_routes_empty_when_absent() {
        let secret = b"shh";
        let auth = [0xDF; 16];
        let attrs = build_accept(17, auth, secret, |_| {});
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert!(acc.framed_routes.is_empty());
    }

    #[test]
    fn session_and_idle_timeout_decoded() {
        let secret = b"shh";
        let auth = [0xE0; 16];
        let attrs = build_accept(18, auth, secret, |r| {
            r.add(rfc::attrs::SESSION_TIMEOUT, 3600u32).unwrap();
            r.add(rfc::attrs::IDLE_TIMEOUT, 600u32).unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.session_timeout, Some(Duration::from_secs(3600)));
        assert_eq!(acc.idle_timeout, Some(Duration::from_secs(600)));
    }

    #[test]
    fn acct_interim_clamped_to_minimum() {
        // RFC 2869 §5.16: interim < 30 s gets clamped up.
        let secret = b"shh";
        let auth = [0xE1; 16];
        let attrs = build_accept(19, auth, secret, |r| {
            r.add(rfc::attrs::ACCT_INTERIM_INTERVAL, 5u32).unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.acct_interim_interval, Some(MIN_ACCT_INTERIM));
    }

    #[test]
    fn acct_interim_passthrough_when_above_minimum() {
        let secret = b"shh";
        let auth = [0xE2; 16];
        let attrs = build_accept(20, auth, secret, |r| {
            r.add(rfc::attrs::ACCT_INTERIM_INTERVAL, 120u32).unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.acct_interim_interval, Some(Duration::from_secs(120)));
    }

    #[test]
    fn class_attribute_round_tripped_verbatim() {
        let secret = b"shh";
        let auth = [0xE3; 16];
        let class_payload = b"opaque-class-bytes\x00\x01\x02";
        let attrs = build_accept(21, auth, secret, |r| {
            r.add(rfc::attrs::CLASS, &class_payload[..]).unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.class.as_deref(), Some(&class_payload[..]));
    }

    #[test]
    fn malformed_mppe_key_yields_auth_error() {
        // MPPE key wire format requires salt(2) + at least one
        // 16-byte encrypted block. Inject 1 byte → decrypt fails →
        // AuthError::Malformed.
        let secret = b"shh";
        let auth = [0xF0; 16];
        let attrs = build_accept(22, auth, secret, |r| {
            r.add_vsa(microsoft::attrs::MS_MPPE_SEND_KEY, &[0x42][..])
                .unwrap();
        });
        let err = decode_accept(&attrs, secret, &auth).unwrap_err();
        assert!(
            matches!(err, AuthError::Malformed("MPPE key decrypt failed")),
            "got {err:?}"
        );
    }

    #[test]
    fn dns_and_nbns_servers_decoded() {
        let secret = b"shh";
        let auth = [0xF1; 16];
        let attrs = build_accept(23, auth, secret, |r| {
            r.add_vsa(
                microsoft::attrs::MS_PRIMARY_DNS_SERVER,
                Ipv4Addr::new(8, 8, 8, 8),
            )
            .unwrap();
            r.add_vsa(
                microsoft::attrs::MS_SECONDARY_DNS_SERVER,
                Ipv4Addr::new(8, 8, 4, 4),
            )
            .unwrap();
            r.add_vsa(
                microsoft::attrs::MS_PRIMARY_NBNS_SERVER,
                Ipv4Addr::new(10, 0, 0, 5),
            )
            .unwrap();
            r.add_vsa(
                microsoft::attrs::MS_SECONDARY_NBNS_SERVER,
                Ipv4Addr::new(10, 0, 0, 6),
            )
            .unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.primary_dns, Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(acc.secondary_dns, Some(Ipv4Addr::new(8, 8, 4, 4)));
        assert_eq!(acc.primary_nbns, Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(acc.secondary_nbns, Some(Ipv4Addr::new(10, 0, 0, 6)));
    }

    #[test]
    fn framed_mtu_and_netmask_decoded() {
        let secret = b"shh";
        let auth = [0xF2; 16];
        let attrs = build_accept(24, auth, secret, |r| {
            r.add(rfc::attrs::FRAMED_MTU, 1400u32).unwrap();
            r.add(
                rfc::attrs::FRAMED_IP_NETMASK,
                Ipv4Addr::new(255, 255, 255, 0),
            )
            .unwrap();
        });
        let acc = decode_accept(&attrs, secret, &auth).unwrap();
        assert_eq!(acc.framed_mtu, Some(1400));
        assert_eq!(acc.framed_netmask, Some(Ipv4Addr::new(255, 255, 255, 0)));
    }
}
