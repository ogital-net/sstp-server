//! In-process metrics registry.
//!
//! No external `metrics` / `prometheus` dependency yet — a handful of
//! atomic counters and gauges cover everything the control socket
//! needs to render `show stat`. The fixed event vocabulary lives
//! here as one `pub static` per metric so call sites can
//! `metrics::FOO.inc()` without going through a `&'static str`
//! lookup or a recorder installation step.
//!
//! All counters are `AtomicU64` with `Ordering::Relaxed` — these are
//! monotonic event counters, not synchronisation primitives, and the
//! occasional small reorder between two of them across CPUs is
//! tolerable. Histograms come later if we need them; for v0.1 the
//! kernel PPP unit (`ip -s link show pppN`) is the source of truth
//! for byte/packet accounting, and connection-level latency lives in
//! the trace logs.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Monotonic counter. `Relaxed` is the right ordering — counter
/// updates do not synchronise other memory.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    #[allow(dead_code)] // wired in when byte-counter event surfaces land
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Signed gauge — sessions can come and go from any worker. Signed so
/// a counter mismatch shows up as a negative number rather than
/// wrapping to `u64::MAX`.
#[derive(Debug, Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    pub const fn new() -> Self {
        Self(AtomicI64::new(0))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

// --- Connection lifecycle -------------------------------------------------

pub static CONNECTIONS_ACCEPTED: Counter = Counter::new();
pub static CONNECTIONS_ACTIVE: Gauge = Gauge::new();
pub static HANDSHAKE_FAILURES: Counter = Counter::new();

// --- Auth -----------------------------------------------------------------

pub static AUTH_ACCEPT: Counter = Counter::new();
pub static AUTH_REJECT: Counter = Counter::new();

// --- Session teardown ----------------------------------------------------

pub static SESSION_TEARDOWN_CLEAN: Counter = Counter::new();
pub static SESSION_TEARDOWN_ADMIN: Counter = Counter::new();
pub static SESSION_TEARDOWN_COA: Counter = Counter::new();
pub static SESSION_TEARDOWN_SHUTDOWN: Counter = Counter::new();
/// TLS post-handshake records observed on the kmod data path,
/// broken down by record content type ([RFC 8446] §B.1, surfaced
/// via `TLS_GET_RECORD_TYPE` cmsg). Every such event ends the
/// session: cooperative rekey across the kmod boundary is not
/// implemented and not planned for v0.x (matches HAProxy's AWS-LC
/// + kTLS posture, see [`crate::crypto::rekey`]). The per-type
/// breakdown is here so a deployment can tell whether they're
/// actually seeing `KeyUpdate` / `NewSessionTicket` (handshake
/// records) versus alerts versus exotic content types.
pub static SESSION_TEARDOWN_REKEY_HANDSHAKE: Counter = Counter::new();
pub static SESSION_TEARDOWN_REKEY_ALERT: Counter = Counter::new();
pub static SESSION_TEARDOWN_REKEY_OTHER: Counter = Counter::new();
pub static SESSION_PANICS: Counter = Counter::new();

// --- Crypto binding ------------------------------------------------------

pub static CRYPTO_BINDING_FAILURES: Counter = Counter::new();

// --- NP-mode filter (TUN backend only) -----------------------------------
//
// Network-layer (IPv4 / IPv6) PPP frames carried inside SSTP `Data`
// packets must be dropped until IPCP / IPV6CP converges ([RFC 1661]
// §3.2 "Network-Layer Protocol Phase"; mirrors the kernel's
// `PPPIOCSNPMODE(NPMODE_DROP)` semantics in `ppp_generic`). On the
// kmod backend the kernel enforces this for us; on the TUN backend
// the gate lives in `session::run` and increments these counters
// when it fires.
//
// `pre_ipcp`: frame arrived before the data path was brought up.
// `mru_exceeded`: frame body exceeded the negotiated MTU.
pub static NP_FILTER_DROPS_PRE_IPCP: Counter = Counter::new();
pub static NP_FILTER_DROPS_MRU: Counter = Counter::new();

// --- Logging backpressure ------------------------------------------------

pub static LOG_LINES_DROPPED: Counter = Counter::new();

/// Render every metric as a HAProxy-style `name: value\n` block,
/// suitable for the control socket's `show stat` response. Allocation
/// happens here, not at metric-update time — call sites stay
/// allocation-free on the hot path.
///
/// Output is stable: one line per metric, names in the order declared
/// above, no header line. Designed to be diff-friendly across
/// snapshots and easy to grep.
pub fn render_stats() -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(512);
    let _ = writeln!(
        out,
        "sstp_connections_accepted: {}",
        CONNECTIONS_ACCEPTED.get()
    );
    let _ = writeln!(out, "sstp_connections_active: {}", CONNECTIONS_ACTIVE.get());
    let _ = writeln!(out, "sstp_handshake_failures: {}", HANDSHAKE_FAILURES.get());
    let _ = writeln!(out, "sstp_auth_accept: {}", AUTH_ACCEPT.get());
    let _ = writeln!(out, "sstp_auth_reject: {}", AUTH_REJECT.get());
    let _ = writeln!(
        out,
        "sstp_session_teardown_clean: {}",
        SESSION_TEARDOWN_CLEAN.get()
    );
    let _ = writeln!(
        out,
        "sstp_session_teardown_admin: {}",
        SESSION_TEARDOWN_ADMIN.get()
    );
    let _ = writeln!(
        out,
        "sstp_session_teardown_coa: {}",
        SESSION_TEARDOWN_COA.get()
    );
    let _ = writeln!(
        out,
        "sstp_session_teardown_shutdown: {}",
        SESSION_TEARDOWN_SHUTDOWN.get()
    );
    let _ = writeln!(
        out,
        "sstp_session_teardown_rekey_handshake: {}",
        SESSION_TEARDOWN_REKEY_HANDSHAKE.get()
    );
    let _ = writeln!(
        out,
        "sstp_session_teardown_rekey_alert: {}",
        SESSION_TEARDOWN_REKEY_ALERT.get()
    );
    let _ = writeln!(
        out,
        "sstp_session_teardown_rekey_other: {}",
        SESSION_TEARDOWN_REKEY_OTHER.get()
    );
    let _ = writeln!(out, "sstp_session_panics: {}", SESSION_PANICS.get());
    let _ = writeln!(
        out,
        "sstp_crypto_binding_failures: {}",
        CRYPTO_BINDING_FAILURES.get()
    );
    let _ = writeln!(
        out,
        "sstp_np_filter_drops_pre_ipcp: {}",
        NP_FILTER_DROPS_PRE_IPCP.get()
    );
    let _ = writeln!(
        out,
        "sstp_np_filter_drops_mru: {}",
        NP_FILTER_DROPS_MRU.get()
    );
    let _ = writeln!(out, "sstp_log_lines_dropped: {}", LOG_LINES_DROPPED.get());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_and_gauge_smoke() {
        let c = Counter::new();
        c.inc();
        c.add(4);
        assert_eq!(c.get(), 5);
        let g = Gauge::new();
        g.inc();
        g.inc();
        g.dec();
        assert_eq!(g.get(), 1);
    }

    #[test]
    fn render_stats_lists_every_metric() {
        let s = render_stats();
        for name in [
            "sstp_connections_accepted",
            "sstp_connections_active",
            "sstp_handshake_failures",
            "sstp_auth_accept",
            "sstp_auth_reject",
            "sstp_session_teardown_clean",
            "sstp_session_teardown_admin",
            "sstp_session_teardown_coa",
            "sstp_session_teardown_shutdown",
            "sstp_session_teardown_rekey_handshake",
            "sstp_session_teardown_rekey_alert",
            "sstp_session_teardown_rekey_other",
            "sstp_session_panics",
            "sstp_crypto_binding_failures",
            "sstp_np_filter_drops_pre_ipcp",
            "sstp_np_filter_drops_mru",
            "sstp_log_lines_dropped",
        ] {
            assert!(s.contains(name), "missing {name} in:\n{s}");
        }
    }
}
