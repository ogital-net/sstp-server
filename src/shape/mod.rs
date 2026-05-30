//! Per-session traffic shaping on the `pppN` / `tun` netdev.
//!
//! ## Scope
//!
//! Foundation only. This module owns:
//!
//! - The wire-agnostic [`ShapingPolicy`] type that the auth bridge
//!   populates from RADIUS Access-Accept attributes and the session
//!   bring-up path consumes.
//! - A parser for the [`Mikrotik-Rate-Limit`] VSA (vendor 14988,
//!   attr 8) — the de-facto standard for PPP/VPN shaping, honoured
//!   by RouterOS, accel-ppp, MPD5, and most third-party RADIUS
//!   dictionaries. See [`mikrotik`].
//! - A [`Shaper`] that owns a `NETLINK_ROUTE` socket and exposes
//!   `apply` / `clear` against an interface index. **The netlink
//!   wire-up is not yet implemented** — both methods currently
//!   return `Ok(())` after logging a TODO. The kernel-side types
//!   and constants the wire-up needs live in [`tc`] so that the
//!   missing piece is encoder bodies, not research.
//!
//! ## Why netlink directly (not shell out to `tc`)
//!
//! Same posture as [`crate::kppp::netlink`]: hand-rolled wire format
//! against `<linux/pkt_sched.h>` to keep the dependency tree flat
//! and the bring-up path syscall-bounded rather than fork+exec
//! bounded. CoA-driven reshape (RADIUS Disconnect-Request →
//! reinstall qdisc on the live unit) becomes a single transaction
//! once the wire-up lands.
//!
//! ## Direction convention
//!
//! Mikrotik names rates from the **client's** point of view:
//! `rx` = client receives = server transmits (egress on `pppN`);
//! `tx` = client transmits = server receives (ingress on `pppN`).
//! [`ShapingPolicy`] uses `egress` / `ingress` to make the kernel
//! mapping unambiguous.
//!
//! [`Mikrotik-Rate-Limit`]: https://wiki.mikrotik.com/wiki/Manual:RADIUS_Client/vendor_dictionary

#![allow(
    dead_code, // FUTURE: consumed once the auth bridge lifts the VSA into `AuthAccept` and the session bring-up path drives `Shaper::apply`.
    clippy::doc_markdown, // Mikrotik / RouterOS / GbE / PPPoE etc. are intentional prose, not Rust identifiers.
)]

pub mod mikrotik;
pub mod tc;

use std::io;

/// A single direction's rate-shaping parameters.
///
/// Rates and burst sizes are unsigned 64-bit so the type can carry
/// 10 GbE deployments without truncation. Bursts are optional: a
/// `None` field means "use the kernel/qdisc default" rather than
/// "no burst at all", matching how `Mikrotik-Rate-Limit` treats
/// elided fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateSpec {
    /// Sustained rate, **bits per second**.
    pub rate_bps: u64,
    /// Peak / burst rate, bits per second. `None` → no separate
    /// burst rate (kernel uses `rate_bps` for both).
    pub burst_rate_bps: Option<u64>,
    /// Threshold above which `burst_rate_bps` applies, bits per
    /// second. `None` → kernel default (typically `rate_bps * 0.75`).
    pub burst_threshold_bps: Option<u64>,
    /// How long the burst rate may be sustained, seconds. `None` →
    /// kernel / Mikrotik default of 1 second.
    pub burst_time_secs: Option<u32>,
    /// Minimum guaranteed rate when contending with other classes,
    /// bits per second. `None` → no minimum (best effort).
    pub min_rate_bps: Option<u64>,
}

impl RateSpec {
    /// Construct a flat rate cap with no burst / minimum semantics.
    #[must_use]
    pub const fn flat(rate_bps: u64) -> Self {
        Self {
            rate_bps,
            burst_rate_bps: None,
            burst_threshold_bps: None,
            burst_time_secs: None,
            min_rate_bps: None,
        }
    }
}

/// Per-session traffic-shaping policy.
///
/// Constructed by the auth bridge from a RADIUS Access-Accept and
/// applied by the session bring-up path against the kernel-assigned
/// interface index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShapingPolicy {
    /// Server → client (egress on `pppN` / `tun`). Maps to
    /// Mikrotik-Rate-Limit's `rx-rate`.
    pub egress: Option<RateSpec>,
    /// Client → server (ingress on `pppN` / `tun`). Maps to
    /// Mikrotik-Rate-Limit's `tx-rate`. Implemented as an ingress
    /// policer / drop-on-overrate, not a true shaper, because Linux
    /// only schedules packets in the egress direction.
    pub ingress: Option<RateSpec>,
    /// HTB / qdisc class priority (0 = highest). Mikrotik exposes
    /// 1-8; `None` = leave at the qdisc default.
    pub priority: Option<u8>,
}

impl ShapingPolicy {
    /// Returns `true` if both directions are unset, i.e. there is
    /// nothing for the kernel to do.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.egress.is_none() && self.ingress.is_none()
    }
}

/// Errors surfaced by [`Shaper`] operations.
#[derive(Debug, thiserror::Error)]
pub enum ShapeError {
    /// Underlying `NETLINK_ROUTE` socket I/O failed.
    #[error("netlink: {0}")]
    Netlink(#[source] io::Error),
    /// Kernel returned a non-zero errno on a `tc` request.
    #[error("kernel rejected {op}: errno {errno}")]
    Kernel {
        op: &'static str,
        errno: i32,
    },
}

/// Owns a `NETLINK_ROUTE` socket scoped to traffic-control work.
///
/// Constructed once per session bring-up; dropped after `apply`.
/// Reusing one `Shaper` across sessions is safe but not currently
/// done — bring-up cost is dominated by the kernel-side qdisc /
/// class allocation, not the socket open.
#[derive(Debug)]
pub struct Shaper {
    // No fd field yet — the wire-up lands with the encoder bodies
    // in `tc::*`. Keeping the struct so callers can take a `&mut
    // Shaper` today and grow into it without a signature change.
    _private: (),
}

impl Shaper {
    /// Open a fresh `NETLINK_ROUTE` socket for `tc` operations.
    #[allow(clippy::unnecessary_wraps)] // FUTURE: socket(2) failure becomes a real error variant.
    pub fn open() -> Result<Self, ShapeError> {
        // FUTURE: `socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
        // NETLINK_ROUTE)` + bind, mirroring `kppp::netlink::RtNetlink::open`.
        Ok(Self { _private: () })
    }

    /// Install `policy` on the netdev with the given `ifindex`.
    ///
    /// Idempotent in spirit: replaces any existing root qdisc on
    /// the interface. Calling on an interface that has never been
    /// shaped is also valid.
    pub fn apply(&mut self, ifindex: u32, policy: &ShapingPolicy) -> Result<(), ShapeError> {
        if policy.is_empty() {
            return self.clear(ifindex);
        }
        // FUTURE: build & send
        //   1. RTM_NEWQDISC kind=htb on root, replace
        //   2. RTM_NEWTCLASS one leaf class with rate/ceil/burst
        //      from policy.egress
        //   3. RTM_NEWQDISC kind=ingress on ffff:fff1
        //   4. RTM_NEWTFILTER kind=u32 with police action from
        //      policy.ingress, attached to ingress
        // See `tc::*` for the kernel struct layouts and attribute
        // IDs needed.
        tracing::debug!(
            target: "shape",
            ifindex,
            ?policy,
            "shape::apply: foundation only \u{2014} netlink wire-up TODO"
        );
        Ok(())
    }

    /// Remove all qdiscs / classes / filters this `Shaper` may have
    /// installed on `ifindex`. Safe to call against a fresh netdev.
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)] // FUTURE: real netlink wire-up uses both.
    pub fn clear(&mut self, ifindex: u32) -> Result<(), ShapeError> {
        // FUTURE: RTM_DELQDISC root, RTM_DELQDISC ingress.
        tracing::debug!(
            target: "shape",
            ifindex,
            "shape::clear: foundation only \u{2014} netlink wire-up TODO"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shaping_policy_empty_when_default() {
        assert!(ShapingPolicy::default().is_empty());
    }

    #[test]
    fn shaping_policy_non_empty_when_either_direction_set() {
        let p = ShapingPolicy {
            egress: Some(RateSpec::flat(1_000_000)),
            ..ShapingPolicy::default()
        };
        assert!(!p.is_empty());

        let p = ShapingPolicy {
            ingress: Some(RateSpec::flat(500_000)),
            ..ShapingPolicy::default()
        };
        assert!(!p.is_empty());
    }

    #[test]
    fn rate_spec_flat_clears_optionals() {
        let r = RateSpec::flat(2_000_000);
        assert_eq!(r.rate_bps, 2_000_000);
        assert!(r.burst_rate_bps.is_none());
        assert!(r.burst_threshold_bps.is_none());
        assert!(r.burst_time_secs.is_none());
        assert!(r.min_rate_bps.is_none());
    }

    #[test]
    fn shaper_apply_empty_policy_short_circuits() {
        let mut s = Shaper::open().expect("open");
        s.apply(42, &ShapingPolicy::default()).expect("apply");
        s.clear(42).expect("clear");
    }
}
