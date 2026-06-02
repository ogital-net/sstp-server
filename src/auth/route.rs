//! `Framed-Route` (RFC 2865 §5.22) — text-format route directive
//! pushed by the RADIUS authenticator at Access-Accept time.
//!
//! Wire format (ASCII text, up to 253 bytes):
//!
//! ```text
//! <dest>[/<prefix>] <gateway> <metric> [more metrics...]
//! ```
//!
//! - `<dest>` is a dotted-quad IPv4 address.
//! - `/<prefix>` is optional; when omitted, the prefix length
//!   defaults to the IPv4 class boundary (8/16/24 for A/B/C). We
//!   still honour the legacy classful default for inputs without a
//!   `/`, but practically every modern authenticator includes one.
//! - `<gateway>` is dotted-quad. The all-zero address `0.0.0.0` is
//!   the conventional spelling for "the user's own machine" and is
//!   how MikroTik / accel-ppp / FreeRADIUS expect callers to push a
//!   route via the per-session `pppN`. We honour the same shorthand
//!   *and* an explicit gateway equal to `Framed-IP-Address`.
//! - One or more space-separated metrics follow. Per RFC 2865 only
//!   the first ever made it into NAS implementations; we stash it
//!   and ignore the rest.
//!
//! Multiple `Framed-Route` attributes may appear in a single
//! Access-Accept; each is decoded independently. A malformed entry
//! is logged and skipped — the rest of the list still applies.

use std::net::Ipv4Addr;

/// One parsed `Framed-Route` directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramedRoute {
    /// Destination network.
    pub dest: Ipv4Addr,
    /// Prefix length in bits (0..=32).
    pub prefix: u8,
    /// Next-hop gateway, or `None` for "via the user's own
    /// machine" (i.e. install via the per-session netdev with no
    /// `RTA_GATEWAY`). RFC 2865 §5.22: a `0.0.0.0` gateway has
    /// this meaning; we project it to `None` here so callers don't
    /// have to special-case the literal address.
    pub gateway: Option<Ipv4Addr>,
    /// First metric, if supplied. RFC 2865 lists it as mandatory
    /// but real-world dictionaries often omit it; we treat it as
    /// optional and let the kernel apply its default (typically
    /// `RT_TABLE_MAIN` priority 0).
    pub metric: Option<u32>,
}

/// Errors from decoding one `Framed-Route` attribute. Caller logs
/// and drops the offending entry; never fatal to the session.
#[derive(Debug, thiserror::Error)]
pub enum FramedRouteParseError {
    #[error("missing destination")]
    MissingDest,
    #[error("invalid destination: {0}")]
    InvalidDest(String),
    #[error("invalid prefix length: {0}")]
    InvalidPrefix(String),
    #[error("missing gateway")]
    MissingGateway,
    #[error("invalid gateway: {0}")]
    InvalidGateway(String),
    #[error("invalid metric: {0}")]
    InvalidMetric(String),
}

impl FramedRoute {
    /// Decode a single `Framed-Route` value.
    ///
    /// # Errors
    ///
    /// Returns [`FramedRouteParseError`] for malformed input.
    pub fn parse(s: &str) -> Result<Self, FramedRouteParseError> {
        let mut tokens = s.split_ascii_whitespace();

        let dest_tok = tokens.next().ok_or(FramedRouteParseError::MissingDest)?;
        let (dest, prefix) = parse_dest_prefix(dest_tok)?;

        let gw_tok = tokens.next().ok_or(FramedRouteParseError::MissingGateway)?;
        let gw_addr: Ipv4Addr = gw_tok
            .parse()
            .map_err(|_| FramedRouteParseError::InvalidGateway(gw_tok.into()))?;
        let gateway = if gw_addr.is_unspecified() {
            None
        } else {
            Some(gw_addr)
        };

        let metric = match tokens.next() {
            None => None,
            Some(m) => Some(
                m.parse::<u32>()
                    .map_err(|_| FramedRouteParseError::InvalidMetric(m.into()))?,
            ),
        };

        Ok(Self {
            dest,
            prefix,
            gateway,
            metric,
        })
    }
}

fn parse_dest_prefix(tok: &str) -> Result<(Ipv4Addr, u8), FramedRouteParseError> {
    if let Some((addr_part, prefix_part)) = tok.split_once('/') {
        let addr: Ipv4Addr = addr_part
            .parse()
            .map_err(|_| FramedRouteParseError::InvalidDest(addr_part.into()))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| FramedRouteParseError::InvalidPrefix(prefix_part.into()))?;
        if prefix > 32 {
            return Err(FramedRouteParseError::InvalidPrefix(prefix_part.into()));
        }
        Ok((addr, prefix))
    } else {
        let addr: Ipv4Addr = tok
            .parse()
            .map_err(|_| FramedRouteParseError::InvalidDest(tok.into()))?;
        // Classful default per RFC 2865 §5.22.
        let octets = addr.octets();
        let prefix = match octets[0] {
            0..=127 => 8,
            128..=191 => 16,
            _ => 24,
        };
        Ok((addr, prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_prefix_and_gateway_with_metric() {
        let r = FramedRoute::parse("192.168.10.0/24 10.0.0.1 5").unwrap();
        assert_eq!(r.dest, Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(r.prefix, 24);
        assert_eq!(r.gateway, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(r.metric, Some(5));
    }

    #[test]
    fn zero_gateway_means_via_user() {
        let r = FramedRoute::parse("10.20.30.0/24 0.0.0.0").unwrap();
        assert_eq!(r.gateway, None);
        assert_eq!(r.metric, None);
    }

    #[test]
    fn classful_default_prefix() {
        // 10.0.0.0 has no slash; class A → /8.
        let r = FramedRoute::parse("10.0.0.0 0.0.0.0 1").unwrap();
        assert_eq!(r.prefix, 8);
        // 192.168.5.0 has no slash; class C → /24.
        let r = FramedRoute::parse("192.168.5.0 0.0.0.0").unwrap();
        assert_eq!(r.prefix, 24);
    }

    #[test]
    fn extra_metrics_ignored() {
        let r = FramedRoute::parse("172.16.0.0/12 0.0.0.0 1 2 3 -1 400").unwrap();
        assert_eq!(r.dest, Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(r.prefix, 12);
        assert_eq!(r.metric, Some(1));
    }

    #[test]
    fn missing_gateway_errors() {
        assert!(matches!(
            FramedRoute::parse("10.0.0.0/8"),
            Err(FramedRouteParseError::MissingGateway)
        ));
    }

    #[test]
    fn invalid_prefix_errors() {
        assert!(matches!(
            FramedRoute::parse("10.0.0.0/33 0.0.0.0"),
            Err(FramedRouteParseError::InvalidPrefix(_))
        ));
    }
}
