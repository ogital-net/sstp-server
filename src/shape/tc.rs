//! Linux traffic-control wire format mirrors.
//!
//! Foundation only — the constants, message numbers, attribute IDs,
//! and `#[repr(C)]` struct mirrors the encoder will need, ported
//! verbatim from `<linux/pkt_sched.h>` / `<linux/rtnetlink.h>` /
//! `<linux/pkt_cls.h>`. Once [`super::Shaper::apply`] grows real
//! bodies they will reach for the items in this module.
//!
//! ## What the encoder will look like
//!
//! For HTB on `pppN` with one leaf class:
//!
//! ```text
//! 1. RTM_NEWQDISC, NLM_F_REQUEST|NLM_F_ACK|NLM_F_REPLACE
//!    tcmsg { tcm_family=AF_UNSPEC, tcm_ifindex, tcm_handle=HANDLE_ROOT,
//!            tcm_parent=TC_H_ROOT, tcm_info=0 }
//!    TCA_KIND  = "htb\0"
//!    TCA_OPTIONS (nested):
//!        TCA_HTB_INIT = tc_htb_glob { version=3, rate2quantum=10,
//!                                     defcls=DEFAULT_CLS_MINOR }
//! 2. RTM_NEWTCLASS, NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_REPLACE
//!    tcmsg { tcm_handle=HTB_LEAF_HANDLE, tcm_parent=HTB_ROOT_HANDLE }
//!    TCA_KIND  = "htb\0"
//!    TCA_OPTIONS (nested):
//!        TCA_HTB_PARMS = tc_htb_opt { rate, ceil, buffer, cbuffer,
//!                                     quantum, level=0, prio }
//!        TCA_HTB_RTAB  = 256 * u32 rate-table
//!        TCA_HTB_CTAB  = 256 * u32 ceil-table
//! ```
//!
//! For ingress policing (Mikrotik tx-rate maps here):
//!
//! ```text
//! 1. RTM_NEWQDISC kind=ingress on TC_H_INGRESS
//! 2. RTM_NEWTFILTER kind=u32 with police action carrying
//!    tc_police { rate, burst, mtu, action=TC_ACT_DROP }
//! ```
//!
//! ## References
//!
//! - `<linux/pkt_sched.h>` — `tc_ratespec`, `tc_htb_*`, `tc_tbf_qopt`,
//!   `tc_police`.
//! - `<linux/rtnetlink.h>` — `tcmsg`, `RTM_NEW*` numbers, `TC_H_*`
//!   handle helpers.
//! - `<linux/pkt_cls.h>` — `TCA_U32_*` for filter construction.
//! - iproute2 `tc/q_htb.c`, `tc/tc_core.c` (rate-table construction).

#![allow(
    dead_code, // Foundation: types are referenced once `Shaper::apply` grows encoder bodies.
    non_camel_case_types, // Match kernel UAPI names exactly so spec lookup is unambiguous.
    clippy::doc_markdown, // PPPoE / GbE etc. in prose.
)]

use std::mem;

// ---------------------------------------------------------------------------
// rtnetlink message numbers (from <linux/rtnetlink.h>).
// ---------------------------------------------------------------------------

pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_DELQDISC: u16 = 37;
pub const RTM_GETQDISC: u16 = 38;

pub const RTM_NEWTCLASS: u16 = 40;
pub const RTM_DELTCLASS: u16 = 41;
pub const RTM_GETTCLASS: u16 = 42;

pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;

// ---------------------------------------------------------------------------
// Handle helpers.
//
// A handle is a 32-bit `major:minor` pair. The kernel exposes a
// handful of magic values for "root" / "ingress" / "unspecified".
// ---------------------------------------------------------------------------

/// `(major << 16) | minor`. Mirrors `TC_H_MAKE` in
/// `<linux/pkt_sched.h>`.
#[must_use]
pub const fn handle(major: u16, minor: u16) -> u32 {
    ((major as u32) << 16) | (minor as u32)
}

/// `TC_H_ROOT` — egress root.
pub const TC_H_ROOT: u32 = 0xFFFF_FFFF;
/// `TC_H_INGRESS` — ingress qdisc parent.
pub const TC_H_INGRESS: u32 = 0xFFFF_FFF1;
/// `TC_H_UNSPEC`.
pub const TC_H_UNSPEC: u32 = 0;

// ---------------------------------------------------------------------------
// `struct tcmsg` — header for every RTM_*QDISC / *TCLASS / *TFILTER.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Tcmsg {
    pub tcm_family: u8,
    pub _pad1: u8,
    pub _pad2: u16,
    pub tcm_ifindex: i32,
    pub tcm_handle: u32,
    pub tcm_parent: u32,
    pub tcm_info: u32,
}

const _: () = assert!(mem::size_of::<Tcmsg>() == 20);

// ---------------------------------------------------------------------------
// Common TCA_* attribute IDs (qdisc / class / filter level).
// ---------------------------------------------------------------------------

pub const TCA_KIND: u16 = 1;
pub const TCA_OPTIONS: u16 = 2;
pub const TCA_STATS: u16 = 3;
pub const TCA_XSTATS: u16 = 4;
pub const TCA_RATE: u16 = 5;
pub const TCA_FCNT: u16 = 6;
pub const TCA_STATS2: u16 = 7;
pub const TCA_STAB: u16 = 8;

// ---------------------------------------------------------------------------
// `struct tc_ratespec` — rate descriptor reused across qdiscs.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcRatespec {
    /// Cell log (rate-table cell size = `1 << cell_log` bytes).
    pub cell_log: u8,
    /// `1` = bytes/sec, `0` = packets/sec for some qdiscs.
    pub linklayer: u8,
    /// Per-packet overhead added to MTU (e.g. PPPoE = 8).
    pub overhead: u16,
    /// Cell alignment (legacy; usually 0).
    pub cell_align: i16,
    /// MPU — minimum packet unit, bytes.
    pub mpu: u16,
    /// Rate in **bytes per second**.
    pub rate: u32,
}

const _: () = assert!(mem::size_of::<TcRatespec>() == 12);

// ---------------------------------------------------------------------------
// HTB.
// ---------------------------------------------------------------------------

/// `enum` values for HTB attributes inside `TCA_OPTIONS` (a nested
/// rtattr block on a `*qdisc` or `*tclass` message).
pub mod htb {
    pub const TCA_HTB_UNSPEC: u16 = 0;
    pub const TCA_HTB_PARMS: u16 = 1;
    pub const TCA_HTB_INIT: u16 = 2;
    pub const TCA_HTB_CTAB: u16 = 3;
    pub const TCA_HTB_RTAB: u16 = 4;
    pub const TCA_HTB_DIRECT_QLEN: u16 = 5;
    pub const TCA_HTB_RATE64: u16 = 6;
    pub const TCA_HTB_CEIL64: u16 = 7;

    /// HTB protocol version (`<linux/pkt_sched.h>` defines as `3 << 16`).
    pub const HTB_VER: u32 = 3 << 16;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcHtbGlob {
    /// `htb::HTB_VER`.
    pub version: u32,
    /// `rate / quantum` — controls how often a class is visited.
    pub rate2quantum: u32,
    /// Default class minor handle (packets that don't match a
    /// filter go here).
    pub defcls: u32,
    pub debug: u32,
    pub direct_pkts: u32,
}

const _: () = assert!(mem::size_of::<TcHtbGlob>() == 20);

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcHtbOpt {
    pub rate: TcRatespec,
    pub ceil: TcRatespec,
    /// Burst size for `rate`, bytes.
    pub buffer: u32,
    /// Burst size for `ceil`, bytes.
    pub cbuffer: u32,
    pub quantum: u32,
    /// 0 = leaf class; >0 = inner.
    pub level: u32,
    pub prio: u32,
}

const _: () = assert!(mem::size_of::<TcHtbOpt>() == 44);

// ---------------------------------------------------------------------------
// TBF (Token Bucket Filter) — simpler shaper, candidate for
// per-direction caps when HTB's class machinery is overkill.
// ---------------------------------------------------------------------------

pub mod tbf {
    pub const TCA_TBF_UNSPEC: u16 = 0;
    pub const TCA_TBF_PARMS: u16 = 1;
    pub const TCA_TBF_RTAB: u16 = 2;
    pub const TCA_TBF_PTAB: u16 = 3;
    pub const TCA_TBF_RATE64: u16 = 4;
    pub const TCA_TBF_PRATE64: u16 = 5;
    pub const TCA_TBF_BURST: u16 = 6;
    pub const TCA_TBF_PBURST: u16 = 7;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcTbfQopt {
    pub rate: TcRatespec,
    pub peakrate: TcRatespec,
    pub limit: u32,
    pub buffer: u32,
    pub mtu: u32,
}

const _: () = assert!(mem::size_of::<TcTbfQopt>() == 36);

// ---------------------------------------------------------------------------
// Police action (used for ingress drop-on-overrate).
// ---------------------------------------------------------------------------

/// `TC_ACT_*` verdicts (`<linux/pkt_cls.h>`).
pub const TC_ACT_OK: i32 = 0;
pub const TC_ACT_RECLASSIFY: i32 = 1;
pub const TC_ACT_SHOT: i32 = 2;
pub const TC_ACT_PIPE: i32 = 3;
pub const TC_ACT_STOLEN: i32 = 4;
pub const TC_ACT_QUEUED: i32 = 5;
pub const TC_ACT_REPEAT: i32 = 6;
pub const TC_ACT_REDIRECT: i32 = 7;

/// `TC_POLICE_OK` etc. — return values from the police action
/// when its rate is exceeded; the kernel maps these to `TC_ACT_*`.
pub const TC_POLICE_UNSPEC: i32 = TC_ACT_OK;
pub const TC_POLICE_OK: i32 = TC_ACT_OK;
pub const TC_POLICE_RECLASSIFY: i32 = TC_ACT_RECLASSIFY;
pub const TC_POLICE_SHOT: i32 = TC_ACT_SHOT;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcPolice {
    pub index: u32,
    /// `TC_POLICE_*` action when rate is exceeded.
    pub action: i32,
    pub limit: u32,
    pub burst: u32,
    pub mtu: u32,
    pub rate: TcRatespec,
    pub peakrate: TcRatespec,
    pub refcnt: i32,
    pub bindcnt: i32,
    pub capab: u32,
}

const _: () = assert!(mem::size_of::<TcPolice>() == 56);

// ---------------------------------------------------------------------------
// Rate table.
//
// Older kernels require a 256-entry `u32` rate table accompanying any
// `tc_ratespec` so the data path can convert `size → time` without
// dividing. Modern kernels (>= 3.3) accept `TCA_*_RATE64` and skip
// the table, but iproute2 still emits it for compatibility. We mirror
// the iproute2 `tc_calc_rtable` algorithm.
// ---------------------------------------------------------------------------

/// Number of entries in an HTB / TBF rate table.
pub const RTAB_LEN: usize = 256;

/// HTB kind string ("htb\0") as it appears in `TCA_KIND`.
pub const KIND_HTB: &[u8] = b"htb\0";
/// Ingress qdisc kind string.
pub const KIND_INGRESS: &[u8] = b"ingress\0";
/// TBF kind string.
pub const KIND_TBF: &[u8] = b"tbf\0";
/// `u32` filter kind string.
pub const KIND_U32: &[u8] = b"u32\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_packs_major_minor() {
        assert_eq!(handle(0x0001, 0x0010), 0x0001_0010);
        assert_eq!(handle(0xFFFE, 0x0001), 0xFFFE_0001);
    }

    #[test]
    fn handle_root_and_ingress_constants() {
        // Spot-check against the kernel header values.
        assert_eq!(TC_H_ROOT, 0xFFFF_FFFF);
        assert_eq!(TC_H_INGRESS, 0xFFFF_FFF1);
    }

    #[test]
    fn struct_sizes_match_kernel_uapi() {
        // The const _: () = assert! lines above already check at
        // compile time; this test is a sanity duplicate so a
        // failure shows up in `cargo test` output too.
        assert_eq!(mem::size_of::<Tcmsg>(), 20);
        assert_eq!(mem::size_of::<TcRatespec>(), 12);
        assert_eq!(mem::size_of::<TcHtbGlob>(), 20);
        assert_eq!(mem::size_of::<TcHtbOpt>(), 44);
        assert_eq!(mem::size_of::<TcTbfQopt>(), 36);
        assert_eq!(mem::size_of::<TcPolice>(), 56);
    }
}
