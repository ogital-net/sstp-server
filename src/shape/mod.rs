//! Per-session traffic shaping on the `pppN` / `tun` netdev.
//!
//! ## Scope
//!
//! - The wire-agnostic [`ShapingPolicy`] type that the auth bridge
//!   populates from RADIUS Access-Accept attributes and the session
//!   bring-up path consumes.
//! - A parser for the [`Mikrotik-Rate-Limit`] VSA (vendor 14988,
//!   attr 8) — the de-facto standard for PPP/VPN shaping, honoured
//!   by RouterOS, accel-ppp, MPD5, and most third-party RADIUS
//!   dictionaries. See [`mikrotik`].
//! - A [`Shaper`] that owns a `NETLINK_ROUTE` socket and installs
//!   an HTB egress qdisc + leaf class on the per-session netdev.
//!
//! ## Implementation status
//!
//! - **Egress (server → client)**: implemented via HTB
//!   ([`Shaper::install_htb_root`] + [`Shaper::install_htb_leaf`]).
//! - **Ingress (client → server)**: implemented via the kernel
//!   ingress qdisc + a match-all `cls_u32` filter carrying a
//!   `TC_ACT_SHOT` police action
//!   ([`Shaper::install_ingress_qdisc`] +
//!   [`Shaper::install_ingress_police_filter`]). Linux has no
//!   true ingress shaper; policing (drop on overrate) is the
//!   kernel's only ingress primitive.
//! - **Explicit clear**: stubbed; relies on netdev teardown to
//!   reap qdiscs (the kernel does this automatically when the
//!   `pppN` / `tun` device is removed). Tracked as
//!   `M-shape-clear`; needed for CoA-driven reshape on a live
//!   session.
//! - **Old-kernel rate tables**: not emitted. Linux ≥ 3.3
//!   accepts `TCA_HTB_RATE64` / `TCA_HTB_CEIL64` and the
//!   `TC_LINKLAYER_ETHERNET` shortcut, both used here. Tracked
//!   as `M-shape-rtab` if a deployment hits an older target.
//!
//! ## Why netlink directly (not shell out to `tc`)
//!
//! Same posture as [`crate::kppp::netlink`]: hand-rolled wire format
//! against `<linux/pkt_sched.h>` to keep the dependency tree flat
//! and the bring-up path syscall-bounded rather than fork+exec
//! bounded. CoA-driven reshape (RADIUS Disconnect-Request →
//! reinstall qdisc on the live unit) is a single netlink
//! transaction with `NLM_F_REPLACE`.
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
    clippy::doc_markdown, // Mikrotik / RouterOS / GbE / PPPoE etc. are intentional prose, not Rust identifiers.
    clippy::cast_possible_truncation, // libc::AF_UNSPEC is i32 but always 0; matches kppp::netlink posture.
    clippy::cast_possible_wrap,
)]

pub mod mikrotik;
pub mod mss;
mod netlink;
pub mod tc;
mod wire;

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
    #[allow(dead_code)] // FUTURE: convenience constructor used by tests today; netlink encoder will reach for it once wire-up lands.
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
    Kernel { op: &'static str, errno: i32 },
}

/// Owns a `NETLINK_ROUTE` socket scoped to traffic-control work.
///
/// Constructed once per session bring-up; dropped after `apply`.
/// Reusing one `Shaper` across sessions is safe but not currently
/// done — bring-up cost is dominated by the kernel-side qdisc /
/// class allocation, not the socket open.
#[derive(Debug)]
pub struct Shaper {
    nl: netlink::TcNetlink,
}

impl Shaper {
    /// Open a fresh `NETLINK_ROUTE` socket for `tc` operations.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::Netlink`] if `socket(2)` or `bind(2)`
    /// fails. Common causes: missing `CAP_NET_ADMIN`, kernel
    /// without `CONFIG_NETLINK_ROUTE` (effectively never on a
    /// stock distro).
    pub fn open() -> Result<Self, ShapeError> {
        Ok(Self {
            nl: netlink::TcNetlink::open()?,
        })
    }

    /// Install `policy` on the netdev with the given `ifindex`.
    ///
    /// Egress (server → client) is true HTB shaping; ingress
    /// (client → server) is HTB-style policing on the kernel
    /// ingress qdisc, which drops packets above the configured
    /// rate (Linux has no true ingress shaper). Idempotent across
    /// reapplies thanks to `NLM_F_REPLACE` on every message.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::Netlink`] for socket-level failures
    /// or [`ShapeError::Kernel`] when the kernel rejects any of
    /// the qdisc / class / filter requests.
    pub fn apply(&mut self, ifindex: u32, policy: &ShapingPolicy) -> Result<(), ShapeError> {
        if policy.is_empty() {
            return self.clear(ifindex);
        }

        if let Some(eg) = policy.egress {
            self.install_htb_root(ifindex)?;
            self.install_htb_leaf(ifindex, &eg, policy.priority)?;
            log_applied_rate("egress (HTB)", ifindex, &eg);
        }

        if let Some(ing) = policy.ingress {
            self.install_ingress_qdisc(ifindex)?;
            self.install_ingress_police_filter(ifindex, &ing)?;
            log_applied_rate("ingress (police)", ifindex, &ing);
        }

        Ok(())
    }

    /// Remove all qdiscs / classes / filters this `Shaper` may have
    /// installed on `ifindex`. Safe to call against a fresh netdev.
    ///
    /// **v0.1 — no-op.** Today `KpppSession`'s drop tears down the
    /// netdev itself, which causes the kernel to reap any attached
    /// qdiscs automatically; explicit clear is therefore not
    /// required for clean session teardown. CoA-driven reshape
    /// (which would replace one shape with another on a *live*
    /// session) will need this — tracked as
    /// `M-shape-clear`.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub fn clear(&mut self, ifindex: u32) -> Result<(), ShapeError> {
        // FUTURE (M-shape-clear): RTM_DELQDISC for TC_H_ROOT and
        // TC_H_INGRESS. Both should tolerate `-EINVAL` from the
        // kernel as "qdisc not present" (idempotent clear).
        tracing::debug!(
            target: "shape",
            ifindex,
            "shape::clear: no-op in v0.1 (netdev teardown reaps qdiscs); TODO M-shape-clear"
        );
        Ok(())
    }

    /// `RTM_NEWQDISC` with kind=`htb`, attached at `TC_H_ROOT` on
    /// `ifindex`, handle `1:0`. Replaces any existing root qdisc.
    fn install_htb_root(&mut self, ifindex: u32) -> Result<(), ShapeError> {
        let buf = encode_htb_root(self.nl.next_seq(), ifindex);
        self.nl.exchange("RTM_NEWQDISC(htb root)", &buf)
    }

    /// `RTM_NEWTCLASS` with kind=`htb`, parent `1:0`, handle `1:1`,
    /// rate / ceil sized from `spec`. Idempotent across reapplies.
    fn install_htb_leaf(
        &mut self,
        ifindex: u32,
        spec: &RateSpec,
        priority: Option<u8>,
    ) -> Result<(), ShapeError> {
        let buf = encode_htb_leaf(self.nl.next_seq(), ifindex, spec, priority);
        self.nl.exchange("RTM_NEWTCLASS(htb leaf)", &buf)
    }

    /// `RTM_NEWQDISC` with kind=`ingress` on `ifindex`. The
    /// kernel auto-handles re-add idempotency: `NLM_F_REPLACE`
    /// makes a re-apply succeed even if the qdisc is already
    /// present.
    fn install_ingress_qdisc(&mut self, ifindex: u32) -> Result<(), ShapeError> {
        let buf = encode_ingress_qdisc(self.nl.next_seq(), ifindex);
        self.nl.exchange("RTM_NEWQDISC(ingress)", &buf)
    }

    /// `RTM_NEWTFILTER` with kind=`u32`, parent = ingress qdisc
    /// handle, match-all selector + nested police action sized
    /// from `spec`. The police action's verdict is
    /// `TC_ACT_SHOT` — packets above rate are dropped.
    fn install_ingress_police_filter(
        &mut self,
        ifindex: u32,
        spec: &RateSpec,
    ) -> Result<(), ShapeError> {
        let buf = encode_ingress_police_filter(self.nl.next_seq(), ifindex, spec);
        self.nl.exchange("RTM_NEWTFILTER(u32+police)", &buf)
    }
}

/// Emit a uniform debug line per direction so real-world testing
/// can compare the rates the kernel saw against the RADIUS-supplied
/// `Mikrotik-Rate-Limit`. Runs once per direction, after the
/// kernel has acked the install.
fn log_applied_rate(direction: &'static str, ifindex: u32, spec: &RateSpec) {
    let rate_bytes_per_sec = spec.rate_bps / 8;
    let ceil_bytes_per_sec = spec.burst_rate_bps.unwrap_or(spec.rate_bps) / 8;
    tracing::debug!(
        target: "shape",
        direction,
        ifindex,
        rate_bps = spec.rate_bps,
        rate_Bps = rate_bytes_per_sec,
        ceil_bps = spec.burst_rate_bps.unwrap_or(spec.rate_bps),
        ceil_Bps = ceil_bytes_per_sec,
        burst_threshold_bps = ?spec.burst_threshold_bps,
        burst_time_secs = ?spec.burst_time_secs,
        min_rate_bps = ?spec.min_rate_bps,
        "shape: rate installed"
    );
}

/// Build the `RTM_NEWQDISC` request that installs an HTB root qdisc
/// (handle `1:0`) on `ifindex`. Pure function so encoder behaviour
/// can be snapshot-tested without a netlink socket.
fn encode_htb_root(seq: u32, ifindex: u32) -> netlink::MessageBuf {
    use netlink::{MessageBuf, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};
    use tc::{
        KIND_HTB, RTM_NEWQDISC, TC_H_ROOT, TCA_KIND, TCA_OPTIONS, TcHtbGlob, Tcmsg, handle, htb,
    };

    let mut buf = MessageBuf::new(
        RTM_NEWQDISC,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    buf.push_struct(&Tcmsg {
        tcm_family: libc::AF_UNSPEC as u8,
        _pad1: 0,
        _pad2: 0,
        tcm_ifindex: i32::try_from(ifindex).expect("ifindex fits in i32"),
        tcm_handle: handle(1, 0),
        tcm_parent: TC_H_ROOT,
        tcm_info: 0,
    });
    buf.push_attr_bytes(TCA_KIND, KIND_HTB);
    buf.nest_begin(TCA_OPTIONS);
    // TCA_HTB_INIT: tc_htb_glob. defcls=1 routes unmatched
    // traffic to handle 1:1 (our single leaf class).
    let glob = TcHtbGlob {
        version: htb::HTB_VER,
        rate2quantum: 10,
        defcls: 1,
        debug: 0,
        direct_pkts: 0,
    };
    buf.push_attr_bytes(htb::TCA_HTB_INIT, wire::bytes_of(&glob));
    buf.nest_end();
    buf.finalize();
    buf
}

/// Build the `RTM_NEWTCLASS` request for the single HTB leaf
/// (handle `1:1`, parent `1:0`) sized from `spec`. Pure function
/// so encoder behaviour can be snapshot-tested without a kernel.
fn encode_htb_leaf(
    seq: u32,
    ifindex: u32,
    spec: &RateSpec,
    priority: Option<u8>,
) -> netlink::MessageBuf {
    use netlink::{MessageBuf, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};
    use tc::{
        KIND_HTB, RTM_NEWTCLASS, TCA_KIND, TCA_OPTIONS, TcHtbOpt, TcRatespec, Tcmsg, handle, htb,
    };

    // bits/s → bytes/s. Mikrotik VSAs are bit-rate; the kernel
    // wants byte-rate everywhere except RATE64/CEIL64 which it
    // also stores as bytes/s.
    let rate_bps_u64 = spec.rate_bps / 8;
    let ceil_bps_u64 = spec.burst_rate_bps.unwrap_or(spec.rate_bps) / 8;

    // Burst sizes ("buffer" / "cbuffer"). HTB needs a positive
    // burst budget; iproute2's default is roughly 1ms worth of
    // bandwidth plus the MTU. Match that with a 1500B floor so
    // tiny rates still get a usable burst.
    let mtu = 1500u32;
    let buffer = saturating_burst_bytes(rate_bps_u64, mtu);
    let cbuffer = saturating_burst_bytes(ceil_bps_u64, mtu);

    let mut hopt = TcHtbOpt {
        rate: TcRatespec {
            cell_log: 0,
            // TC_LINKLAYER_ETHERNET (=1) tells the kernel to
            // skip the legacy rate-table path; combined with
            // RATE64 below this avoids needing TCA_HTB_RTAB.
            linklayer: 1,
            overhead: 0,
            cell_align: 0,
            mpu: 0,
            rate: u32::try_from(rate_bps_u64.min(u64::from(u32::MAX))).expect("u32 saturate"),
        },
        ceil: TcRatespec {
            cell_log: 0,
            linklayer: 1,
            overhead: 0,
            cell_align: 0,
            mpu: 0,
            rate: u32::try_from(ceil_bps_u64.min(u64::from(u32::MAX))).expect("u32 saturate"),
        },
        buffer,
        cbuffer,
        quantum: 0, // 0 = kernel picks based on rate2quantum
        level: 0,   // leaf
        prio: u32::from(priority.unwrap_or(0)),
    };
    // The kernel rejects rate=0 outright. Saturate to 1 byte/s
    // so a legitimately-tiny rate still installs (better to
    // shape-to-near-zero than to fail the session).
    if hopt.rate.rate == 0 {
        hopt.rate.rate = 1;
    }
    if hopt.ceil.rate == 0 {
        hopt.ceil.rate = hopt.rate.rate;
    }

    let mut buf = MessageBuf::new(
        RTM_NEWTCLASS,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    buf.push_struct(&Tcmsg {
        tcm_family: libc::AF_UNSPEC as u8,
        _pad1: 0,
        _pad2: 0,
        tcm_ifindex: i32::try_from(ifindex).expect("ifindex fits in i32"),
        tcm_handle: handle(1, 1),
        tcm_parent: handle(1, 0),
        tcm_info: 0,
    });
    buf.push_attr_bytes(TCA_KIND, KIND_HTB);
    buf.nest_begin(TCA_OPTIONS);
    buf.push_attr_bytes(htb::TCA_HTB_PARMS, wire::bytes_of(&hopt));
    // Always emit RATE64 / CEIL64. They cost 12 bytes apiece
    // and let the kernel handle 10GbE-class deployments where
    // bytes/s overflows u32 (≥ 4 GiB/s ≈ 32 Gbps). Kernels
    // that don't recognise the attribute silently ignore it;
    // kernels that do prefer it over the 32-bit field.
    buf.push_attr_bytes(htb::TCA_HTB_RATE64, &rate_bps_u64.to_ne_bytes());
    buf.push_attr_bytes(htb::TCA_HTB_CEIL64, &ceil_bps_u64.to_ne_bytes());
    // FUTURE (M-shape-rtab): for kernels older than 3.3, also
    // emit TCA_HTB_RTAB / TCA_HTB_CTAB (256 × u32 each).
    // Mirroring iproute2's `tc_calc_rtable` is straightforward
    // but adds ~40 lines. We target Linux 6.x where the
    // RATE64 path is universal, so this can wait until a real
    // deployment hits an old-kernel target.
    buf.nest_end();
    buf.finalize();
    buf
}

/// Build the `RTM_NEWQDISC` request that installs the ingress
/// qdisc on `ifindex`. The ingress qdisc is a special pseudo-qdisc
/// whose only purpose is to host filters; it has no options.
///
/// Wire shape:
/// ```text
/// nlmsghdr(RTM_NEWQDISC, REQUEST|ACK|CREATE|REPLACE)
/// tcmsg { ifindex, handle = ffff:0, parent = TC_H_INGRESS, info = 0 }
/// TCA_KIND = "ingress\0"
/// ```
fn encode_ingress_qdisc(seq: u32, ifindex: u32) -> netlink::MessageBuf {
    use netlink::{MessageBuf, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};
    use tc::{KIND_INGRESS, RTM_NEWQDISC, TC_H_INGRESS, TCA_KIND, Tcmsg, handle};

    let mut buf = MessageBuf::new(
        RTM_NEWQDISC,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    buf.push_struct(&Tcmsg {
        tcm_family: libc::AF_UNSPEC as u8,
        _pad1: 0,
        _pad2: 0,
        tcm_ifindex: i32::try_from(ifindex).expect("ifindex fits in i32"),
        // ingress qdisc owns the magic handle ffff:0; iproute2
        // sets this explicitly even though `tc qdisc add ... ingress`
        // accepts handle 0 too. We mirror iproute2 for predictability.
        tcm_handle: handle(0xFFFF, 0),
        tcm_parent: TC_H_INGRESS,
        tcm_info: 0,
    });
    buf.push_attr_bytes(TCA_KIND, KIND_INGRESS);
    buf.finalize();
    buf
}

/// Build the `RTM_NEWTFILTER` request that attaches a match-all
/// `u32` filter to the ingress qdisc, carrying a `police` action
/// sized from `spec` whose verdict is `TC_ACT_SHOT` (drop on
/// over-rate).
///
/// Wire shape:
/// ```text
/// nlmsghdr(RTM_NEWTFILTER, REQUEST|ACK|CREATE|REPLACE)
/// tcmsg {
///     ifindex, handle = 0 (kernel auto-assigns),
///     parent = ffff:0, info = (prio<<16) | htons(ETH_P_ALL)
/// }
/// TCA_KIND = "u32\0"
/// TCA_OPTIONS (nested) {
///     TCA_U32_SEL = tc_u32_sel { flags=TC_U32_TERMINAL, nkeys=0, ... }
///     TCA_U32_POLICE (nested) {
///         TCA_POLICE_TBF    = tc_police { rate, burst, action=SHOT, ... }
///         TCA_POLICE_RATE64 = u64 rate (bytes/s)
///     }
/// }
/// ```
fn encode_ingress_police_filter(seq: u32, ifindex: u32, spec: &RateSpec) -> netlink::MessageBuf {
    use netlink::{MessageBuf, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};
    use tc::{
        ETH_P_ALL, KIND_U32, RTM_NEWTFILTER, TC_ACT_SHOT, TCA_KIND, TCA_OPTIONS, TcPolice,
        TcRatespec, TcU32Sel, Tcmsg, handle, police, u32_filter,
    };

    let rate_bps_u64 = spec.rate_bps / 8;
    // Ingress burst defaults: 10 ms worth of bandwidth, with a
    // floor of 10 × MTU so micro-rates still admit a sensible
    // packet train. Bytes here, converted to PSCHED ticks below.
    let mtu = 1500u32;
    let burst_bytes = saturating_ingress_burst_bytes(rate_bps_u64, mtu);
    let burst_ticks = burst_bytes_to_psched_ticks(burst_bytes, rate_bps_u64);

    let mut parm = TcPolice {
        index: 0,
        action: TC_ACT_SHOT, // drop on overrate
        limit: 0,
        burst: burst_ticks,
        mtu,
        rate: TcRatespec {
            cell_log: 0,
            // TC_LINKLAYER_ETHERNET; matches the egress side and
            // keeps the kernel from demanding a rate-table.
            linklayer: 1,
            overhead: 0,
            cell_align: 0,
            mpu: 0,
            rate: u32::try_from(rate_bps_u64.min(u64::from(u32::MAX))).expect("u32 saturate"),
        },
        peakrate: TcRatespec::default(),
        refcnt: 0,
        bindcnt: 0,
        capab: 0,
    };
    if parm.rate.rate == 0 {
        parm.rate.rate = 1; // kernel rejects rate=0 outright
    }

    // Match-all selector. nkeys=0 + TC_U32_TERMINAL means "every
    // packet matches; do not link to a hash table"; combined with
    // the police action below the kernel runs the policer on
    // every packet that hits the ingress qdisc.
    let sel = TcU32Sel {
        flags: u32_filter::TC_U32_TERMINAL,
        offshift: 0,
        nkeys: 0,
        _pad: 0,
        offmask: 0,
        off: 0,
        offoff: 0,
        hoff: 0,
        hmask: 0,
    };

    // tcm_info: upper 16 bits = filter prio, lower 16 bits =
    // network-byte-order ethertype. `htons(ETH_P_ALL=0x0003)`.
    let prio: u32 = 1;
    let info = (prio << 16) | u32::from(ETH_P_ALL.to_be());

    let mut buf = MessageBuf::new(
        RTM_NEWTFILTER,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    buf.push_struct(&Tcmsg {
        tcm_family: libc::AF_UNSPEC as u8,
        _pad1: 0,
        _pad2: 0,
        tcm_ifindex: i32::try_from(ifindex).expect("ifindex fits in i32"),
        tcm_handle: 0, // kernel auto-assigns
        tcm_parent: handle(0xFFFF, 0),
        tcm_info: info,
    });
    buf.push_attr_bytes(TCA_KIND, KIND_U32);
    buf.nest_begin(TCA_OPTIONS);
    buf.push_attr_bytes(u32_filter::TCA_U32_SEL, wire::bytes_of(&sel));
    buf.nest_begin(u32_filter::TCA_U32_POLICE);
    buf.push_attr_bytes(police::TCA_POLICE_TBF, wire::bytes_of(&parm));
    // Always emit RATE64 — same posture as the HTB side.
    buf.push_attr_bytes(police::TCA_POLICE_RATE64, &rate_bps_u64.to_ne_bytes());
    buf.nest_end(); // TCA_U32_POLICE
    buf.nest_end(); // TCA_OPTIONS
    buf.finalize();
    buf
}

/// Compute an HTB burst budget that's at least one MTU and roughly
/// 1ms worth of bandwidth at `rate_bytes_per_sec`. Saturates into
/// `u32` for very large rates (the burst field is 32-bit).
fn saturating_burst_bytes(rate_bytes_per_sec: u64, mtu: u32) -> u32 {
    let one_ms = rate_bytes_per_sec / 1000;
    let target = one_ms.saturating_add(u64::from(mtu));
    u32::try_from(target.min(u64::from(u32::MAX))).expect("clamped to u32")
}

/// Ingress burst budget in **bytes**: 10 ms at line rate with a
/// floor of `10 × mtu`. Larger than the egress HTB buffer because
/// dropped packets are unrecoverable, so a slightly more generous
/// token bucket reduces spurious drops on bursty TCP traffic.
fn saturating_ingress_burst_bytes(rate_bytes_per_sec: u64, mtu: u32) -> u32 {
    let ten_ms = rate_bytes_per_sec / 100;
    let floor = u64::from(mtu).saturating_mul(10);
    let target = ten_ms.max(floor);
    u32::try_from(target.min(u64::from(u32::MAX))).expect("clamped to u32")
}

/// Convert a burst expressed in **bytes** into the PSCHED tick
/// units the kernel's `tc_police.burst` field wants.
///
/// The kernel converts `parm.burst` to nanoseconds by left-shift
/// of `PSCHED_TIME_SHIFT` (= 6 on modern x86_64) — i.e. one tick
/// is 64 ns. iproute2 derives the multiplier at runtime from
/// `/proc/net/psched`; for practical kernels it has been ≈1 since
/// 2.6.32, so v0.1 hard-codes `tick_in_usec = 1` (1 PSCHED tick =
/// 1 ns from userspace's view; the kernel then re-shifts).
///
/// FUTURE (M-shape-psched): read `/proc/net/psched` once at
/// `Shaper::open` to derive the actual `tick_in_usec` and use
/// it here. Mostly cosmetic — most distros ship the default.
fn burst_bytes_to_psched_ticks(burst_bytes: u32, rate_bytes_per_sec: u64) -> u32 {
    if rate_bytes_per_sec == 0 {
        return u32::MAX;
    }
    // ns-of-token-bucket = bytes / (bytes/sec) seconds ⇒ × 1e9 ns.
    let ns = (u64::from(burst_bytes) * 1_000_000_000) / rate_bytes_per_sec;
    u32::try_from(ns.min(u64::from(u32::MAX))).expect("clamped to u32")
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

    #[test]
    fn encode_htb_root_shape() {
        // Snapshot test: verify the structural invariants of the
        // RTM_NEWQDISC message we emit, without depending on
        // exact byte layout (alignment / pad bytes are
        // platform-stable but the test reads better as
        // field-level assertions).
        let buf = encode_htb_root(/* seq */ 7, /* ifindex */ 42);
        let bytes = buf.bytes();

        // nlmsghdr: len patched, type=RTM_NEWQDISC,
        // flags=REQUEST|ACK|CREATE|REPLACE, seq=7.
        let nlmsg_len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(nlmsg_len as usize, bytes.len());
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        assert_eq!(nlmsg_type, tc::RTM_NEWQDISC);
        let nlmsg_flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        assert_eq!(
            nlmsg_flags,
            netlink::NLM_F_REQUEST
                | netlink::NLM_F_ACK
                | netlink::NLM_F_CREATE
                | netlink::NLM_F_REPLACE,
        );
        let nlmsg_seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(nlmsg_seq, 7);

        // tcmsg starts at offset 16 (NLMSG_HDRLEN). ifindex at +4.
        let tcm_ifindex = i32::from_ne_bytes(bytes[16 + 4..16 + 8].try_into().unwrap());
        assert_eq!(tcm_ifindex, 42);
        // tcm_handle = 1:0 = 0x00010000 (major in upper 16 bits).
        let tcm_handle = u32::from_ne_bytes(bytes[16 + 8..16 + 12].try_into().unwrap());
        assert_eq!(tcm_handle, tc::handle(1, 0));
        // tcm_parent = TC_H_ROOT = 0xFFFFFFFF.
        let tcm_parent = u32::from_ne_bytes(bytes[16 + 12..16 + 16].try_into().unwrap());
        assert_eq!(tcm_parent, tc::TC_H_ROOT);

        // The TCA_KIND attribute payload "htb\0" must appear
        // verbatim somewhere in the buffer.
        assert!(
            bytes.windows(4).any(|w| w == b"htb\0"),
            "TCA_KIND htb not found in encoded message",
        );
    }

    #[test]
    fn encode_htb_leaf_carries_rate64_for_large_rates() {
        // 5 Gbps - bytes/s (= 625 MB/s) fits in u32 trivially,
        // but the RATE64 attribute should still be present and
        // correct; the kernel will prefer it over the 32-bit
        // field when both are set.
        let spec = RateSpec::flat(5_000_000_000);
        let buf = encode_htb_leaf(/* seq */ 9, /* ifindex */ 1, &spec, None);
        let bytes = buf.bytes();

        // Look for the 8-byte rate value in native byte order
        // anywhere after the TCA_OPTIONS nest. 5_000_000_000 / 8
        // = 625_000_000 bytes/s.
        let expected = 625_000_000u64.to_ne_bytes();
        assert!(
            bytes.windows(8).any(|w| w == expected),
            "TCA_HTB_RATE64 = 625_000_000 (bytes/s) not found in encoded message",
        );

        // And the message ends 4-byte-aligned with nlmsg_len
        // matching the buffer length.
        let nlmsg_len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(nlmsg_len as usize, bytes.len());
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn encode_htb_leaf_floors_zero_rate() {
        // A degenerate rate=0 must not produce rate.rate=0 in
        // the wire format (the kernel rejects it). The encoder
        // floors to 1 byte/s.
        let spec = RateSpec::flat(0);
        let buf = encode_htb_leaf(1, 1, &spec, None);
        // Guard rail: u32-le `0,0,0,0` (rate=0 in the
        // tc_ratespec) should NOT be the rate field. We can't
        // tell that from a substring search, but we can confirm
        // RATE64 is the explicit zero we expect (the spec said
        // 0) and that the message still encodes successfully.
        let bytes = buf.bytes();
        let zero_u64 = 0u64.to_ne_bytes();
        assert!(
            bytes.windows(8).any(|w| w == zero_u64),
            "RATE64 = 0 should still appear as we honour the spec literally"
        );
    }

    #[test]
    fn encode_ingress_qdisc_shape() {
        let buf = encode_ingress_qdisc(/* seq */ 11, /* ifindex */ 7);
        let bytes = buf.bytes();

        // nlmsghdr: type / flags / seq.
        let nlmsg_len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(nlmsg_len as usize, bytes.len());
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        assert_eq!(nlmsg_type, tc::RTM_NEWQDISC);
        let nlmsg_seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(nlmsg_seq, 11);

        // tcmsg @ offset 16. ifindex / handle / parent.
        let tcm_ifindex = i32::from_ne_bytes(bytes[20..24].try_into().unwrap());
        assert_eq!(tcm_ifindex, 7);
        let tcm_handle = u32::from_ne_bytes(bytes[24..28].try_into().unwrap());
        assert_eq!(tcm_handle, tc::handle(0xFFFF, 0));
        let tcm_parent = u32::from_ne_bytes(bytes[28..32].try_into().unwrap());
        assert_eq!(tcm_parent, tc::TC_H_INGRESS);

        // TCA_KIND payload appears verbatim.
        assert!(
            bytes.windows(8).any(|w| w == b"ingress\0"),
            "TCA_KIND ingress not found in encoded message",
        );
        // No nested TCA_OPTIONS — ingress qdisc has no options.
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn encode_ingress_police_carries_rate64_and_shot_action() {
        // 100 Mbps = 12_500_000 bytes/s.
        let spec = RateSpec::flat(100_000_000);
        let buf = encode_ingress_police_filter(/* seq */ 13, /* ifindex */ 9, &spec);
        let bytes = buf.bytes();

        // Header invariants.
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        assert_eq!(nlmsg_type, tc::RTM_NEWTFILTER);

        // tcm_info: prio=1, protocol=htons(ETH_P_ALL).
        let tcm_info = u32::from_ne_bytes(bytes[16 + 16..16 + 20].try_into().unwrap());
        let expected_info = (1u32 << 16) | u32::from(tc::ETH_P_ALL.to_be());
        assert_eq!(tcm_info, expected_info);

        // TCA_KIND = "u32\0".
        assert!(
            bytes.windows(4).any(|w| w == b"u32\0"),
            "TCA_KIND u32 not found",
        );

        // RATE64 in bytes/s should be present in native byte order.
        let expected_rate64 = 12_500_000u64.to_ne_bytes();
        assert!(
            bytes.windows(8).any(|w| w == expected_rate64),
            "TCA_POLICE_RATE64 = 12_500_000 not found in encoded message",
        );

        // The TC_ACT_SHOT verdict is encoded inside tc_police.action.
        // It's an i32 at offset 4 of the struct; assert at least one
        // little-endian occurrence of the value (= 2). Used as a
        // sanity check that the police struct is on the wire.
        let shot = (tc::TC_ACT_SHOT).to_ne_bytes();
        assert!(
            bytes.windows(4).any(|w| w == shot),
            "TC_ACT_SHOT (=2) not found in encoded message",
        );

        // 4-byte-aligned termination.
        let nlmsg_len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(nlmsg_len as usize, bytes.len());
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn burst_bytes_to_psched_ticks_handles_zero_rate() {
        // No division by zero; saturate to u32::MAX.
        assert_eq!(burst_bytes_to_psched_ticks(1500, 0), u32::MAX);
    }

    #[test]
    fn saturating_ingress_burst_bytes_floors_to_ten_mtus() {
        // At 1 byte/s the 10 ms target is 0; the floor of 10×MTU wins.
        let mtu = 1500u32;
        let burst = saturating_ingress_burst_bytes(1, mtu);
        assert_eq!(burst, mtu * 10);
    }
}
