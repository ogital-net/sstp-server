//! Parser for the `Mikrotik-Rate-Limit` RADIUS VSA (vendor 14988,
//! attribute 8).
//!
//! ## Wire format
//!
//! The attribute is a free-form ASCII string. Fields are
//! whitespace-separated; each field is either a single value or a
//! `rx/tx` pair. Trailing fields may be omitted; once a field is
//! omitted, all later fields must also be omitted (positional, no
//! named fields). The full grammar, in order:
//!
//! ```text
//! rate            [burst-rate     [burst-threshold [burst-time [priority [min-rate]]]]]
//! rx-rate[/tx]    rx-bst[/tx-bst]  rx-th[/tx-th]    rx-bt[/tx-bt]  prio    rx-min[/tx-min]
//! ```
//!
//! Rate / threshold values use a SI suffix (`k`, `M`, `G`,
//! case-insensitive) on a base of 1000; e.g. `512k` = 512 000 bps,
//! `2M` = 2 000 000 bps. A bare integer is bits per second.
//! Mikrotik also accepts decimal mantissas (`2.5M`).
//!
//! Burst time is in seconds (integer). Priority is an integer
//! 1..=8, lower = higher priority.
//!
//! ## Direction mapping
//!
//! Mikrotik names from the **client's** point of view: `rx` is
//! what the client receives. We translate to
//! [`ShapingPolicy::egress`] (server → client) and
//! [`ShapingPolicy::ingress`] (client → server) at parse time so
//! consumers don't have to.
//!
//! ## References
//!
//! - <https://wiki.mikrotik.com/wiki/Manual:RADIUS_Client/vendor_dictionary>
//! - <https://help.mikrotik.com/docs/spaces/ROS/pages/2031671/RADIUS+Client>

use super::{RateSpec, ShapingPolicy};

/// Errors that can surface while parsing the VSA payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The attribute value was empty.
    #[error("Mikrotik-Rate-Limit: empty value")]
    Empty,
    /// A field that should have been `value` or `rx/tx` had more
    /// than one slash.
    #[error("Mikrotik-Rate-Limit: malformed pair (too many slashes) in field {field}")]
    BadPair { field: &'static str },
    /// A numeric field could not be parsed.
    #[error("Mikrotik-Rate-Limit: invalid number {value:?} in field {field}")]
    BadNumber { field: &'static str, value: String },
    /// Priority was outside 1..=8.
    #[error("Mikrotik-Rate-Limit: priority {0} out of range 1..=8")]
    PriorityRange(i64),
    /// More fields than the grammar permits.
    #[error("Mikrotik-Rate-Limit: extra fields after position 6")]
    Extra,
}

/// Parse a `Mikrotik-Rate-Limit` attribute value into a typed
/// [`ShapingPolicy`].
///
/// Whitespace around the whole value is trimmed; internal
/// whitespace runs are treated as a single separator.
pub fn parse(value: &str) -> Result<ShapingPolicy, ParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut fields = trimmed.split_ascii_whitespace();

    let rate = parse_pair(fields.next().ok_or(ParseError::Empty)?, "rate")?;
    let burst_rate = fields
        .next()
        .map(|f| parse_pair(f, "burst-rate"))
        .transpose()?;
    let burst_threshold = fields
        .next()
        .map(|f| parse_pair(f, "burst-threshold"))
        .transpose()?;
    let burst_time = fields
        .next()
        .map(|f| parse_pair_u32(f, "burst-time"))
        .transpose()?;
    let priority = fields.next().map(parse_priority).transpose()?;
    let min_rate = fields
        .next()
        .map(|f| parse_pair(f, "min-rate"))
        .transpose()?;

    if fields.next().is_some() {
        return Err(ParseError::Extra);
    }

    let egress = build_spec(
        rate.rx,
        burst_rate.map(|p| p.rx),
        burst_threshold.map(|p| p.rx),
        burst_time.map(|p| p.rx),
        min_rate.map(|p| p.rx),
    );
    let ingress = build_spec(
        rate.tx,
        burst_rate.map(|p| p.tx),
        burst_threshold.map(|p| p.tx),
        burst_time.map(|p| p.tx),
        min_rate.map(|p| p.tx),
    );

    Ok(ShapingPolicy {
        egress,
        ingress,
        priority,
    })
}

#[derive(Debug, Clone, Copy)]
struct Pair<T> {
    /// Mikrotik-rx (egress / server → client).
    rx: T,
    /// Mikrotik-tx (ingress / client → server).
    tx: T,
}

/// Parse a `rx[/tx]` field of bits-per-second values.
fn parse_pair(field: &str, name: &'static str) -> Result<Pair<u64>, ParseError> {
    let mut halves = field.splitn(3, '/');
    let rx = parse_bps(halves.next().expect("splitn yields at least one"), name)?;
    let tx = match halves.next() {
        Some(s) => parse_bps(s, name)?,
        None => rx,
    };
    if halves.next().is_some() {
        return Err(ParseError::BadPair { field: name });
    }
    Ok(Pair { rx, tx })
}

/// Parse a `rx[/tx]` field of integer seconds.
fn parse_pair_u32(field: &str, name: &'static str) -> Result<Pair<u32>, ParseError> {
    let mut halves = field.splitn(3, '/');
    let rx = parse_u32(halves.next().expect("splitn yields at least one"), name)?;
    let tx = match halves.next() {
        Some(s) => parse_u32(s, name)?,
        None => rx,
    };
    if halves.next().is_some() {
        return Err(ParseError::BadPair { field: name });
    }
    Ok(Pair { rx, tx })
}

fn parse_priority(field: &str) -> Result<u8, ParseError> {
    let n: i64 = field.parse().map_err(|_| ParseError::BadNumber {
        field: "priority",
        value: field.to_owned(),
    })?;
    if !(1..=8).contains(&n) {
        return Err(ParseError::PriorityRange(n));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(n as u8)
}

fn parse_u32(s: &str, field: &'static str) -> Result<u32, ParseError> {
    s.parse().map_err(|_| ParseError::BadNumber {
        field,
        value: s.to_owned(),
    })
}

/// Parse a bit-rate with optional SI suffix: `512k`, `2M`, `1.5G`,
/// or a bare integer.
fn parse_bps(s: &str, field: &'static str) -> Result<u64, ParseError> {
    let bad = || ParseError::BadNumber {
        field,
        value: s.to_owned(),
    };
    if s.is_empty() {
        return Err(bad());
    }

    let last = s.as_bytes()[s.len() - 1];
    let (num, multiplier) = match last {
        b'k' | b'K' => (&s[..s.len() - 1], 1_000_u64),
        b'm' | b'M' => (&s[..s.len() - 1], 1_000_000_u64),
        b'g' | b'G' => (&s[..s.len() - 1], 1_000_000_000_u64),
        _ => (s, 1_u64),
    };

    if num.is_empty() {
        return Err(bad());
    }

    // Try integer first to avoid float rounding for the common case.
    if let Ok(n) = num.parse::<u64>() {
        return n.checked_mul(multiplier).ok_or_else(bad);
    }
    let f: f64 = num.parse().map_err(|_| bad())?;
    if !f.is_finite() || f < 0.0 {
        return Err(bad());
    }
    // The four multiplier values (1, 1k, 1M, 1G) all fit in f64 exactly;
    // the precision-loss lint fires on the type of the cast, not the
    // values, and is suppressed here intentionally.
    #[allow(clippy::cast_precision_loss)]
    let multiplier_f = multiplier as f64;
    let scaled = f * multiplier_f;
    #[allow(clippy::cast_precision_loss)]
    let u64_max_f = u64::MAX as f64;
    if !scaled.is_finite() || scaled < 0.0 || scaled > u64_max_f {
        return Err(bad());
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(scaled as u64)
}

fn build_spec(
    rate: u64,
    burst_rate: Option<u64>,
    burst_threshold: Option<u64>,
    burst_time: Option<u32>,
    min_rate: Option<u64>,
) -> Option<RateSpec> {
    if rate == 0 && burst_rate.is_none() && min_rate.is_none() {
        return None;
    }
    Some(RateSpec {
        rate_bps: rate,
        burst_rate_bps: burst_rate,
        burst_threshold_bps: burst_threshold,
        burst_time_secs: burst_time,
        min_rate_bps: min_rate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value_rejected() {
        assert_eq!(parse(""), Err(ParseError::Empty));
        assert_eq!(parse("   "), Err(ParseError::Empty));
    }

    #[test]
    fn flat_symmetric_rate() {
        let p = parse("1M").expect("parse");
        assert_eq!(p.egress.unwrap().rate_bps, 1_000_000);
        assert_eq!(p.ingress.unwrap().rate_bps, 1_000_000);
        assert!(p.priority.is_none());
    }

    #[test]
    fn asymmetric_rate() {
        let p = parse("512k/2M").expect("parse");
        assert_eq!(p.egress.unwrap().rate_bps, 512_000);
        assert_eq!(p.ingress.unwrap().rate_bps, 2_000_000);
    }

    #[test]
    fn full_six_field_form() {
        // Real-world example from the Mikrotik manual.
        let p = parse("512k/2M 1M/4M 64k/256k 5/10 4 16k/64k").expect("parse");
        let eg = p.egress.unwrap();
        let ig = p.ingress.unwrap();

        assert_eq!(eg.rate_bps, 512_000);
        assert_eq!(eg.burst_rate_bps, Some(1_000_000));
        assert_eq!(eg.burst_threshold_bps, Some(64_000));
        assert_eq!(eg.burst_time_secs, Some(5));
        assert_eq!(eg.min_rate_bps, Some(16_000));

        assert_eq!(ig.rate_bps, 2_000_000);
        assert_eq!(ig.burst_rate_bps, Some(4_000_000));
        assert_eq!(ig.burst_threshold_bps, Some(256_000));
        assert_eq!(ig.burst_time_secs, Some(10));
        assert_eq!(ig.min_rate_bps, Some(64_000));

        assert_eq!(p.priority, Some(4));
    }

    #[test]
    fn bare_integer_is_bits_per_second() {
        let p = parse("1500000").expect("parse");
        assert_eq!(p.egress.unwrap().rate_bps, 1_500_000);
    }

    #[test]
    fn decimal_with_suffix() {
        let p = parse("2.5M").expect("parse");
        assert_eq!(p.egress.unwrap().rate_bps, 2_500_000);
    }

    #[test]
    fn case_insensitive_suffixes() {
        assert_eq!(parse("1k").unwrap().egress.unwrap().rate_bps, 1_000);
        assert_eq!(parse("1K").unwrap().egress.unwrap().rate_bps, 1_000);
        assert_eq!(parse("1m").unwrap().egress.unwrap().rate_bps, 1_000_000);
        assert_eq!(parse("1M").unwrap().egress.unwrap().rate_bps, 1_000_000);
        assert_eq!(parse("1g").unwrap().egress.unwrap().rate_bps, 1_000_000_000);
        assert_eq!(parse("1G").unwrap().egress.unwrap().rate_bps, 1_000_000_000);
    }

    #[test]
    fn priority_range_validated() {
        let err = parse("1M 2M 1M 1 0").unwrap_err();
        assert!(matches!(err, ParseError::PriorityRange(0)));
        let err = parse("1M 2M 1M 1 9").unwrap_err();
        assert!(matches!(err, ParseError::PriorityRange(9)));
    }

    #[test]
    fn malformed_pair_rejected() {
        let err = parse("1M/2M/3M").unwrap_err();
        assert!(matches!(err, ParseError::BadPair { .. }));
    }

    #[test]
    fn invalid_number_rejected() {
        let err = parse("1Z").unwrap_err();
        assert!(matches!(err, ParseError::BadNumber { .. }));
        let err = parse("k").unwrap_err();
        assert!(matches!(err, ParseError::BadNumber { .. }));
    }

    #[test]
    fn extra_fields_rejected() {
        let err = parse("1M 1M 1M 1 1 1k extra").unwrap_err();
        assert!(matches!(err, ParseError::Extra));
    }

    #[test]
    fn whitespace_normalised() {
        let p = parse("   1M    2M   ").expect("parse");
        assert_eq!(p.egress.unwrap().rate_bps, 1_000_000);
        assert_eq!(p.egress.unwrap().burst_rate_bps, Some(2_000_000));
    }
}
