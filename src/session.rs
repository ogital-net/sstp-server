//! Per-connection session lifecycle (M6 glue).
//!
//! Each accepted TCP connection becomes a [`run`] task on the I/O
//! worker that accepted it. That task owns the TCP socket, the (future)
//! TLS state, the SSTP state machine, and the in-process PPP control
//! plane for its lifetime; nothing else touches them. Cross-worker
//! interactions — RADIUS CoA-driven disconnect, the control-socket
//! `disable session` command, the SIGTERM drain — go through a bounded
//! [`tokio::sync::mpsc`] channel per session, with a global [`Registry`]
//! mapping [`SessionId`] to a cloneable [`SessionHandle`].
//!
//! The Registry's mutex is **not on the steady-state packet path** —
//! it is only touched at session bring-up, teardown, and control-socket
//! queries.

// `AdminRequested` / `RadiusDisconnect` and the `get` / `is_empty` /
// `peer` surface get their consumers in M7 (control socket) and M4
// (CoA → session lookup). Keep them visible now so the scaffolding
// shape is committed.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::auth::acct_bridge::AcctBridge;
use crate::auth::bridge::AuthBridge;
use crate::cli::DataPathMode;
use crate::crypto;
use crate::crypto::tls::{SslContext, TlsStream};
use crate::kppp::session::KpppSession;
use crate::metrics;
use crate::ppp::{AuthMethod, AuthVerdict, Ppp, PppEvent, PppStep, TimerOwner};
use crate::shape::mss_shared::{SharedMssHandle, SharedMssTable};
use crate::sstp::preamble;

/// Bounded depth for the per-session control channel. Control commands
/// (Disconnect) are rare enough that any backlog past a couple of slots
/// signals a stuck session — we want to drop rather than queue forever.
const CONTROL_CHANNEL_DEPTH: usize = 4;

/// How often the per-worker periodic tick fires. Each tick sends
/// `PeriodicTick` to every session on the worker; sessions check
/// internally whether hello keepalive or accounting interim work is
/// due. 1 s gives ±1 s jitter on the 60 s accounting cadence and
/// the 60 s hello threshold — well within spec tolerance for both.
pub const WORKER_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Monotonic per-process session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);

impl SessionId {
    /// Allocate the next session ID. Wraps at `u64::MAX` (≈585 years
    /// at 1B/s); the wrap-around case is left unhandled because we
    /// will not reach it.
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    #[must_use]
    #[allow(dead_code)] // Used in tests; exposed for future control-socket numeric formatting.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Construct from a raw `u64`. Used by the control socket parser
    /// when an operator types `show session <id>` — there is no
    /// monotonicity check; an unknown id falls out of the [`Registry`]
    /// lookup as `None`.
    #[must_use]
    pub fn from_u64(v: u64) -> Self {
        Self(v)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Reason a session is being torn down via the control channel. Maps
/// to [MS-SSTP] §2.2.14 Call-Disconnect status codes once the SSTP
/// state machine consumes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Operator-initiated (`disable session` on the control socket).
    AdminRequested,
    /// RADIUS CoA Disconnect-Request for this session.
    #[allow(dead_code)]
    // FUTURE: emitted by the CoA receiver once its MPSC handoff to the registry lands.
    RadiusDisconnect,
    /// Process-wide drain in progress (SIGTERM / `shutdown` command).
    ServerShutdown,
}

/// Cross-worker control commands deliverable to a single session.
#[derive(Debug, Clone)]
pub enum ControlCommand {
    Disconnect(DisconnectReason),
    /// Force a TLS 1.3 `KeyUpdate` on this session's TLS stream
    /// ([RFC 8446] §4.6.3). Only honoured on the TUN backend
    /// (userspace owns the TLS record layer there); the kmod
    /// backend rejects with a log line because cooperative rekey
    /// across the kmod ↔ userspace boundary is not implemented
    /// (see [`crate::crypto::rekey`] — matches HAProxy's AWS-LC
    /// posture). The bool is `update_requested`: when true the peer
    /// must respond with its own `KeyUpdate`, which exercises the
    /// receive-side rekey path.
    Rekey {
        request_peer: bool,
    },
    /// Per-worker periodic tick (~1 s). The session checks whether
    /// any periodic work is due:
    /// - Hello keepalive: send SSTP Echo Request if idle > 60 s,
    ///   abort if idle > 120 s ([MS-SSTP] §3.1.2.3).
    /// - Accounting interim: emit an Acct-Status-Type=Interim-Update
    ///   if the configured interval has elapsed since the last record.
    ///
    /// One timerfd per worker drives all sessions — no per-session
    /// timer-wheel entries or timerfd overhead.
    PeriodicTick,
}

/// Cloneable, `Send` handle to a session living on some I/O worker.
///
/// Held by the [`Registry`]; cloned out by the control socket / CoA
/// receiver / drain coordinator when they need to act on a session.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub id: SessionId,
    pub peer: SocketAddr,
    tx: mpsc::Sender<ControlCommand>,
    info: SessionInfoHandle,
}

/// Mutable per-session runtime metadata surfaced via the control
/// socket (`show session [id]`). Updated by the session task at each
/// lifecycle phase; read by the control-socket dispatcher under a
/// brief mutex lock. Off the steady-state packet path.
#[derive(Debug, Default, Clone)]
pub struct SessionInfo {
    /// Set in [`run`] before the TLS handshake starts; lets the
    /// control socket render `uptime`.
    pub started_at: Option<Instant>,
    /// e.g. `"TLSv1.3"` — populated after the TLS handshake.
    pub tls_version: Option<String>,
    /// Negotiated TLS cipher name (libssl convention, e.g.
    /// `"TLS_AES_256_GCM_SHA384"`).
    pub cipher: Option<String>,
    /// Windows correlation id from the SSTP HTTPS preamble (header
    /// `SSTPCORRELATIONID`); useful for cross-referencing client-side
    /// event logs.
    pub correlation_id: Option<String>,
    /// PPP authentication method advertised by the server's LCP.
    /// Always known once `handle_ppp_step` runs; defaulted to PAP
    /// before that.
    pub auth_method: Option<AuthMethod>,
    /// Authenticated peer username (PAP / CHAP / MS-CHAPv2). Set
    /// after RADIUS Access-Accept.
    pub username: Option<String>,
    /// IPv4 address assigned to the client (`Framed-IP-Address`).
    pub assigned_ip: Option<Ipv4Addr>,
    /// Server-side P2P address — same value for every session,
    /// recorded for completeness.
    pub local_ip: Option<Ipv4Addr>,
    /// Kernel netdev name: `pppN` for the kmod backend, `tunN` for
    /// the TUN fallback.
    pub ifname: Option<String>,
    /// Negotiated link MTU on the data path.
    pub mtu: Option<u32>,
    /// `"kmod"` or `"tun"` — backend that owns the steady-state
    /// byte path.
    pub backend: Option<&'static str>,
    /// Egress / ingress rate caps from the RADIUS reply (Mikrotik
    /// VSA today). `None` means unshaped.
    pub shaping: Option<crate::shape::ShapingPolicy>,
}

/// Shared handle to a session's mutable info block. Cheap to clone;
/// short critical sections.
pub type SessionInfoHandle = Arc<Mutex<SessionInfo>>;

#[must_use]
fn new_info_handle() -> SessionInfoHandle {
    Arc::new(Mutex::new(SessionInfo::default()))
}

impl SessionHandle {
    /// Test-only constructor that wires a fresh control channel and
    /// returns both the handle and its receiver. Production code goes
    /// through [`spawn_handle`].
    #[cfg(test)]
    #[must_use]
    pub fn for_test(id: SessionId, peer: SocketAddr) -> (Self, mpsc::Receiver<ControlCommand>) {
        let (tx, rx) = mpsc::channel(CONTROL_CHANNEL_DEPTH);
        (
            Self {
                id,
                peer,
                tx,
                info: new_info_handle(),
            },
            rx,
        )
    }

    /// Snapshot the live [`SessionInfo`] for this session. The
    /// returned struct is a clone — the lock is released before
    /// return.
    #[must_use]
    pub fn info(&self) -> SessionInfo {
        self.info
            .lock()
            .expect("session info mutex poisoned")
            .clone()
    }

    /// Attempt to deliver a control command. Returns `false` if the
    /// session has already exited (receiver dropped) or its control
    /// queue is full.
    pub fn try_send(&self, cmd: ControlCommand) -> bool {
        match self.tx.try_send(cmd) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(id = %self.id, "control channel full; dropping command");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

/// Shared map of active sessions. Cloneable across runtimes.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<HashMap<SessionId, SessionHandle>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, handle: SessionHandle) {
        let mut g = self.inner.lock().expect("session registry poisoned");
        g.insert(handle.id, handle);
    }

    pub fn unregister(&self, id: SessionId) {
        let mut g = self.inner.lock().expect("session registry poisoned");
        g.remove(&id);
    }

    pub fn get(&self, id: SessionId) -> Option<SessionHandle> {
        let g = self.inner.lock().expect("session registry poisoned");
        g.get(&id).cloned()
    }

    /// Snapshot of all live sessions. Cheap clone of the values; the
    /// registry mutex is released before return.
    pub fn snapshot(&self) -> Vec<SessionHandle> {
        let g = self.inner.lock().expect("session registry poisoned");
        g.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        let g = self.inner.lock().expect("session registry poisoned");
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Broadcast a disconnect command to every live session. Used by
    /// the SIGTERM drain coordinator.
    pub fn broadcast_disconnect(&self, reason: DisconnectReason) {
        for h in self.snapshot() {
            h.try_send(ControlCommand::Disconnect(reason));
        }
    }
}

/// Per-connection task entry point.
///
/// Runs on the I/O worker that accepted the connection. The TCP stream,
/// TLS state, (future) SSTP state machine, and (future) PPP control
/// plane are owned here for the session's lifetime; nothing in this
/// task is `Send` once protocol state is in place.
///
/// **v0.1 status (M6a).** The TLS handshake is wired up: the task
/// registers itself, terminates TLS against the shared [`SslContext`],
/// then selects on `(tls_read, control_rx, drain_rx)`. The SSTP HTTPS
/// preamble (M6b), SSTP state machine (M6c) and PPP drive (M6d) land
/// next; until they do, the task discards inbound application bytes
/// after logging the first read.
#[allow(clippy::too_many_arguments)] // session entry point: every arg is essential context
pub async fn run(
    stream: TcpStream,
    peer: SocketAddr,
    id: SessionId,
    registry: Registry,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    mut drain_rx: watch::Receiver<bool>,
    tls_ctx: SslContext,
    auth_bridge: AuthBridge,
    acct_bridge: Option<AcctBridge>,
    local_ip: Ipv4Addr,
    auth_method: AuthMethod,
    data_path: DataPathMode,
    mss_table: Option<Arc<SharedMssTable>>,
    info: SessionInfoHandle,
) {
    info!(%id, %peer, "session accepted");

    {
        let mut g = info.lock().expect("session info mutex poisoned");
        g.started_at = Some(Instant::now());
        g.local_ip = Some(local_ip);
        g.auth_method = Some(auth_method);
    }

    let _registered = RegistrationGuard {
        registry: &registry,
        id,
    };

    // Snapshot the server cert hashes before consuming the TLS context
    // — we hand them to the SSTP FSM once Call Connect Request lands.
    let cert_hash_sha1 = tls_ctx.cert_hash_sha1();
    let cert_hash = tls_ctx.cert_hash_sha256();

    // Phase 1: TLS handshake. Failures here are common in practice
    // (port scanners, readiness probes, TLS-version mismatches) so
    // they are logged at warn — not error — and counted into the
    // single `HANDSHAKE_FAILURES` bucket.
    let mut tls = tokio::select! {
        biased;
        _ = drain_rx.changed() => {
            info!(%id, "session draining before TLS handshake");
            return;
        }
        cmd = control_rx.recv() => {
            if let Some(ControlCommand::Disconnect(reason)) = cmd {
                info!(%id, ?reason, "session control: disconnect before TLS handshake");
            }
            return;
        }
        res = tls_ctx.accept(stream) => match res {
            Ok(t) => t,
            Err(e) => {
                warn!(%id, error = %e, "TLS handshake failed");
                metrics::HANDSHAKE_FAILURES.inc();
                return;
            }
        },
    };
    info!(%id, "TLS handshake completed");

    // Publish negotiated TLS parameters for `show session`. Reuses
    // the same probe `ktls_eligibility` performs — version + cipher
    // names are returned even when the suite isn't kTLS-eligible,
    // so the control socket can render the cipher for any session.
    {
        let elig = tls.ktls_eligibility();
        let mut g = info.lock().expect("session info mutex poisoned");
        g.tls_version = Some(elig.tls_version);
        g.cipher = Some(elig.cipher);
    }

    // kTLS install is *not* invoked here — it happens at kernel-
    // mode kmod attach inside [`handle_ppp_step`]. In kmod mode the
    // data path runs entirely in kernel context; userspace only
    // sends control frames via `SSTP_IOC_SEND_CONTROL`.
    // Installing it earlier would mean either (a) libssl `SSL_write`
    // double-encrypting on subsequent control writes, or (b) needing
    // the raw-fd TX path to be ready before we know whether the
    // session will go kernel-mode at all. Under `--data-path auto`,
    // sessions that fall back to TUN keep using libssl end-to-end
    // and never install kTLS at all.

    // Phase 2: SSTP HTTPS preamble (MS-SSTP §3.2.4.1 / §4.1). The
    // client posts to the well-known URI with `Content-Length:
    // ULONGLONG_MAX`; we validate and respond with `HTTP/1.1 200`.
    // After this exchange the same connection carries raw SSTP
    // frames.
    let preamble = match preamble::handshake(&mut tls).await {
        Ok(p) => p,
        Err(e) => {
            warn!(%id, error = %e, "SSTP preamble failed");
            metrics::HANDSHAKE_FAILURES.inc();
            // Best-effort 400 for protocol-level errors so the
            // client surfaces a meaningful message instead of a
            // bare TCP reset. I/O errors get no response — the
            // socket is already broken.
            if matches!(
                e,
                preamble::PreambleError::Bad(_) | preamble::PreambleError::TooLarge
            ) {
                let _ = preamble::write_error_response(&mut tls).await;
            }
            return;
        }
    };
    info!(
        %id,
        correlation_id = preamble.correlation_id.as_deref().unwrap_or("-"),
        "SSTP HTTPS preamble accepted"
    );
    {
        let mut g = info.lock().expect("session info mutex poisoned");
        g.correlation_id = preamble.correlation_id;
    }

    // Phase 3: drive the SSTP state machine until it terminates.
    // PPP wiring (M6d), the RADIUS bridge (M6e) and Crypto Binding
    // verification (M6f) hook in here as those subsystems land —
    // today the loop accepts a `Call-Connect-Request`, responds with
    // an `Ack`, and would normally signal PPP to start LCP. Without
    // a PPP layer the FSM sits in `Server_Call_Connected_Pending`
    // until the negotiation timer fires and the abort sequence
    // drains the connection.
    drive_sstp(
        id,
        peer,
        tls,
        control_rx,
        drain_rx,
        auth_bridge,
        acct_bridge,
        cert_hash_sha1,
        cert_hash,
        local_ip,
        auth_method,
        data_path,
        mss_table,
        info,
    )
    .await;

    info!(%id, "session ended");
}

/// SSTP state machine driver. Runs after the HTTPS preamble has
/// completed.
///
/// Owns the [`StateMachine`], a single timer slot (the FSM is
/// designed so at most one logical timer is armed at any time across
/// the negotiation / hello / abort / disconnect sub-FSMs), and the
/// inbound packet reassembly buffer. Each iteration of the select
/// converts an external event (drain signal, control command, timer
/// fire, TLS read) into one or more FSM steps, then writes any
/// outbound packets back through the TLS stream.
#[allow(clippy::too_many_lines)] // straight-line event dispatch; splitting hurts readability
#[allow(clippy::too_many_arguments)] // session driver entry point: every arg is essential context
async fn drive_sstp(
    id: SessionId,
    peer: SocketAddr,
    tls: TlsStream,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    mut drain_rx: watch::Receiver<bool>,
    auth_bridge: AuthBridge,
    acct_bridge: Option<AcctBridge>,
    cert_hash_sha1: [u8; 20],
    cert_hash: [u8; 32],
    local_ip: Ipv4Addr,
    auth_method: AuthMethod,
    data_path: DataPathMode,
    mss_table: Option<Arc<SharedMssTable>>,
    info: SessionInfoHandle,
) {
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;
    use tokio::io::unix::AsyncFd;
    use tokio::time::Sleep;

    use crate::kppp::sstp_kmod::{EventRaw, EventType, SSTP_CONTROL_MAX};
    use crate::sstp::frame::{SSTP_HEADER_LEN, SSTP_MAX_PACKET_LEN, write_header};
    use crate::sstp::msg::CALL_CONNECTED_LEN;
    use crate::sstp::state::Timer;
    use crate::sstp::{ControlMessage, Packet, StateMachine, parse_control, parse_control_payload};

    // Wrap the libssl-backed TLS stream in a `TxStream`. In TUN
    // mode, all writes go through libssl. In kmod mode, data frames
    // are handled by the kernel; only control frames route through
    // `SSTP_IOC_SEND_CONTROL` (see `apply_step`).
    let mut tx = TxStream::new(tls);

    let mut ssm = StateMachine::new(cert_hash_sha1, cert_hash);
    let mut tx_buf = [0u8; SSTP_MAX_PACKET_LEN];
    let mut rx_buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    let mut sstp_timer: Option<(Timer, Pin<Box<Sleep>>)> = None;
    let mut ppp: Option<Ppp> = None;
    let mut ppp_timer: Option<(TimerOwner, Pin<Box<Sleep>>)> = None;
    let mut kppp: Option<KpppSession> = None;
    let mut kppp_buf = [0u8; 2048];
    // Per-worker periodic tick state. The worker sends
    // `ControlCommand::PeriodicTick` every WORKER_TICK_INTERVAL;
    // the handler checks these timestamps to decide what work is due.
    let mut last_rx = Instant::now();
    let mut hello_echo_pending = false;
    // Jitter the initial accounting deadline across [0, period) so
    // sessions that start at the same time (reconnect burst) don't
    // all fire their first interim in the same tick. Uses the
    // session ID (monotonic u64) as a cheap deterministic spread —
    // no RNG needed, just distribute evenly across the interval.
    let mut acct_interim_period = Duration::from_secs(60);
    let jitter = Duration::from_millis(id.as_u64() % acct_interim_period.as_secs());
    let mut last_acct_interim = Instant::now()
        .checked_sub(jitter)
        .unwrap_or_else(Instant::now);
    // RAII handle for this session's entry in the shared MSS-clamp
    // set. `None` until IPCP converges and the netdev is up; on drop
    // (session teardown) it removes the interface from the nftables
    // set. `None` for the whole session when clamping is disabled.
    let mut mss_handle: Option<SharedMssHandle> = None;
    // Borrow the owned `Option<Arc<SharedMssTable>>` once so every
    // downstream handler call can pass the (Copy) `Option<&Arc>`
    // without a per-call `as_ref()`. The owned binding stays alive
    // to the end of this scope, keeping the borrow valid; the
    // per-session `SharedMssHandle` (above) holds its own `Arc`
    // clone, so table lifetime is independent of this borrow.
    let mss_table = mss_table.as_ref();
    // Stashed at PAP Accept time (`NeedPapAuth` handler in
    // `handle_ppp_step`), consumed at `NetworkUp` time once the
    // kernel netdev exists. `None` after consumption or when the
    // RADIUS reply carried no shaping VSA.
    let mut pending_shaping: Option<crate::shape::ShapingPolicy> = None;
    // RADIUS-driven session policy (Framed-Route, Class,
    // Session/Idle-Timeout, Acct-Interim-Interval) stashed at
    // Access-Accept time and applied at netdev bring-up.
    let mut pending_policy: Option<crate::auth::SessionPolicy> = None;
    // Set once a kernel-mode `KpppSession` is brought up: a
    // duplicate of the kmod's anon-inode session fd wrapped for
    // tokio readability polling. While `Some`, `tx.tls.read()` is
    // gated off (the kmod owns the byte path) and incoming SSTP
    // control packets arrive as `SSTP_EVT_CONTROL_PACKET` events.
    let mut kmod_async_fd: Option<AsyncFd<crate::kppp::session::FdRef>> = None;
    // Scratch buffer for `SSTP_IOC_RECV_CONTROL`. Sized at the
    // kernel's `SSTP_CONTROL_MAX` so the ioctl never returns
    // `EMSGSIZE`.
    let mut ctrl_buf = vec![0u8; SSTP_CONTROL_MAX];
    // Reused across kmod readability wakeups; the kmod's control
    // queue is bounded so this stays tiny in practice.
    let mut kmod_events: Vec<EventRaw> = Vec::with_capacity(16);
    let auth = AuthCtx {
        peer,
        bridge: &auth_bridge,
        acct: acct_bridge.as_ref(),
    };

    // Accounting state: populated when IPCP converges and the
    // kernel netdev is up. Until then, the [`AcctStopGuard`]'s
    // drop path is a no-op (no Start was ever emitted).
    let mut acct_state: Option<AcctState> = None;
    // Captured at PAP/CHAP/MS-CHAPv2 Accept time, drained at
    // [`PppEvent::NetworkUp`] when the AcctState is finalized.
    let mut pending_username: Option<String> = None;
    // Captured at MS-CHAPv2 Accept time when the authenticator
    // returned both `MS-MPPE-Send-Key` and `MS-MPPE-Recv-Key`
    // (RFC 3079); the Crypto Binding HLAK is `Send-Key || Recv-Key`
    // ([MS-SSTP] §3.2.5.2.2). Drained right after each handler
    // returns by feeding `ssm.on_inner_auth_completed`. PAP / CHAP
    // never set this — they fall through to the ServerBypassHLAuth
    // (zero HLAK) default in [`crate::sstp::binding`].
    let mut pending_hlak: Option<[u8; 32]> = None;
    // Read by [`AcctStopGuard::drop`] to choose the
    // `Acct-Terminate-Cause`. Default `LostCarrier` covers every
    // unscheduled exit (peer-FIN, TLS error, IPCP failure); the
    // few sites with a more specific cause set this explicitly
    // before exiting.
    let acct_cause = std::cell::Cell::new(crate::auth::accounting::SessionEnd::LostCarrier);

    // RADIUS-driven hard session deadline (RFC 2865 §5.27,
    // `Session-Timeout`). `None` until policy applies at
    // `NetworkUp` and the attribute was present.
    let mut session_timeout_deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    // RADIUS-driven idle deadline (RFC 2865 §5.28, `Idle-Timeout`).
    // The deadline fires `Idle-Timeout` seconds after the last
    // observed octet counter movement; the AcctInterim arm
    // re-arms it whenever activity is detected.
    let mut idle_timeout: Option<std::time::Duration> = None;
    let mut idle_timeout_deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    // Snapshot of `last_counters.input_octets + output_octets`
    // captured at the previous AcctInterim tick; compared against
    // the current snapshot to decide whether to re-arm
    // `idle_timeout_deadline`.
    let mut last_activity_octets: u64 = 0;

    // The Drop-guard MUST be declared after the locals it points
    // at — Rust drops in reverse declaration order, so this guard
    // drops first (while the borrowed locals are still alive).
    let _acct_stop_guard = AcctStopGuard {
        bridge: acct_bridge.as_ref().map(std::ptr::from_ref),
        state_ptr: &raw mut acct_state,
        cause_ptr: &raw const acct_cause,
        peer,
    };

    // Spec entry point: `New HTTPS Connection Received` (§3.3.2.1).
    let initial = ssm.on_https_accepted();
    if !handle_sstp_step(
        id,
        &mut tx,
        &initial,
        &mut tx_buf,
        &mut sstp_timer,
        &mut ppp,
        &mut ppp_timer,
        &auth,
        local_ip,
        auth_method,
        &mut kppp,
        data_path,
        &mut pending_shaping,
        &mut pending_policy,
        &mut pending_username,
        &mut pending_hlak,
        &mut acct_state,
        mss_table,
        &mut mss_handle,
        &info,
    )
    .await
    {
        return;
    }

    loop {
        // Drain any HLAK captured by the previous handler iteration
        // (MS-CHAPv2 Accept). Feeding it through
        // `on_inner_auth_completed` updates the SSTP binding state
        // ([MS-SSTP] §3.3.7.1) so the eventual `Call-Connected`
        // Compound MAC is computed against the right key. PAP / CHAP
        // never set `pending_hlak`; their HLAK stays `None` and the
        // ServerBypassHLAuth (zero) default applies.
        if let Some(hlak) = pending_hlak.take() {
            ssm.on_inner_auth_completed(Some(hlak));
            debug!(%id, "SSTP Crypto Binding HLAK applied from MS-CHAPv2 MPPE keys");
        }
        // Lazily wrap the kmod session fd in an `AsyncFd` once a
        // kernel-mode `KpppSession` is brought up. Doing it here
        // (rather than at bring-up time) keeps `handle_ppp_step` free
        // of tokio I/O construction and lets the driver fall back
        // cleanly if the dup fails.
        if kmod_async_fd.is_none()
            && let Some(k) = kppp.as_ref()
            && k.is_kernel()
        {
            match k.kmod_async_fd() {
                Ok(Some(af)) => {
                    debug!(%id, "kmod session fd registered for tokio readability polling");
                    kmod_async_fd = Some(af);
                }
                Ok(None) => {
                    // is_kernel() said yes but kmod_async_fd() said
                    // no — programming error in KpppSession.
                    error!(%id, "kernel-mode KpppSession yielded no kmod fd; tearing session down");
                    return;
                }
                Err(e) => {
                    warn!(%id, error = %e, "failed to register kmod fd with tokio");
                    return;
                }
            }
        }
        // Once the kernel netdev is up and we still have an
        // un-applied `pending_policy`, install Acct-Interim
        // cadence and the Session/Idle deadlines now. Done at the
        // top of the loop (rather than inline at bring-up) so the
        // mutable parent-scope state — `acct_interim_tick`,
        // `session_timeout_deadline`, `idle_timeout_deadline` —
        // doesn't have to thread through `handle_ppp_step`.
        if kppp.is_some()
            && let Some(policy) = pending_policy.take()
        {
            if let Some(period) = policy.acct_interim_interval {
                acct_interim_period = period;
                info!(
                    %id,
                    ?period,
                    "applied RADIUS Acct-Interim-Interval"
                );
            }
            if let Some(dur) = policy.session_timeout {
                session_timeout_deadline = Some(Box::pin(tokio::time::sleep(dur)));
                info!(%id, ?dur, "applied RADIUS Session-Timeout");
            }
            if let Some(dur) = policy.idle_timeout {
                idle_timeout = Some(dur);
                idle_timeout_deadline = Some(Box::pin(tokio::time::sleep(dur)));
                info!(%id, ?dur, "applied RADIUS Idle-Timeout");
            }
        }
        // Wrap each optional timer in a poll_fn so the corresponding
        // select branch is `Poll::Pending` forever when no timer is
        // armed. Borrows on the timer slots end at the `select!`
        // boundary so other arms can mutate them through the apply
        // helpers afterwards.
        let outcome = {
            let sstp_timer_fut = poll_fn(|cx| match sstp_timer.as_mut() {
                Some((_, sleep)) => sleep.as_mut().poll(cx),
                None => Poll::Pending,
            });
            let ppp_timer_fut = poll_fn(|cx| match ppp_timer.as_mut() {
                Some((_, sleep)) => sleep.as_mut().poll(cx),
                None => Poll::Pending,
            });
            // Read one IP packet from the TUN device when the
            // session is on the TUN backend. In kernel-kmod mode the
            // sstp kmod owns the byte path and there is nothing for
            // us to copy.
            let kppp_read_fut = async {
                match kppp.as_ref() {
                    Some(k) if k.is_tun() => k.read_frame(&mut kppp_buf).await,
                    _ => std::future::pending::<std::io::Result<usize>>().await,
                }
            };
            // In kernel mode the kmod has consumed the TCP byte
            // path; `SSL_read` on the same socket would either
            // hang (kernel-TLS RX delivers bytes via the kmod's
            // sk_data_ready callback, not back up through libssl)
            // or get desynced. Gate `tls.read()` to pending and
            // route inbound SSTP control packets through the kmod
            // event channel instead.
            let tls_read_fut = async {
                if kmod_async_fd.is_some() {
                    std::future::pending::<std::io::Result<usize>>().await
                } else {
                    tx.tls.read(&mut chunk).await
                }
            };
            // Wait for the kmod session fd to become readable;
            // resolves to the readability guard so we can
            // `clear_ready()` after draining all queued events to
            // `EAGAIN`. Pending forever when `kmod_async_fd` is
            // `None`.
            let kmod_fut = async {
                match kmod_async_fd.as_ref() {
                    Some(af) => Some(af.readable().await),
                    None => std::future::pending().await,
                }
            };
            // RADIUS Session-Timeout / Idle-Timeout deadlines —
            // pending until policy installs them.
            let session_timeout_fut = poll_fn(|cx| match session_timeout_deadline.as_mut() {
                Some(s) => s.as_mut().poll(cx),
                None => Poll::Pending,
            });
            let idle_timeout_fut = poll_fn(|cx| match idle_timeout_deadline.as_mut() {
                Some(s) => s.as_mut().poll(cx),
                None => Poll::Pending,
            });
            tokio::select! {
                biased;
                _ = drain_rx.changed() => DriverEvent::Drain,
                c = control_rx.recv() => DriverEvent::Control(c),
                () = session_timeout_fut => DriverEvent::SessionTimeout,
                () = idle_timeout_fut => DriverEvent::IdleTimeout,
                () = sstp_timer_fut => DriverEvent::SstpTimer,
                () = ppp_timer_fut => DriverEvent::PppTimer,
                r = kppp_read_fut => DriverEvent::KpppRead(r),
                g = kmod_fut => {
                    // Drain events into the hoisted Vec while we
                    // still hold the readiness guard, then clear
                    // readiness in one shot. The kmod's control
                    // queue is bounded (SSTP_CTRL_Q_CAP) so the
                    // Vec stays tiny.
                    kmod_events.clear();
                    let mut io_err: Option<std::io::Error> = None;
                    match g {
                        Some(Err(e)) => io_err = Some(e),
                        Some(Ok(mut guard)) => {
                            loop {
                                match kppp.as_ref().and_then(|k| {
                                    k.read_event().transpose()
                                }) {
                                    None => {
                                        // Queue empty (Ok(None))
                                        // *or* kppp went away mid-
                                        // iteration. Clear and bail.
                                        guard.clear_ready();
                                        break;
                                    }
                                    Some(Ok(ev)) => kmod_events.push(ev),
                                    Some(Err(e)) => {
                                        io_err = Some(std::io::Error::other(e.to_string()));
                                        break;
                                    }
                                }
                            }
                        }
                        None => unreachable!("kmod_fut returned None despite Some(AsyncFd)"),
                    }
                    DriverEvent::KmodEvents { io_err }
                },
                r = tls_read_fut => DriverEvent::Read(r),
            }
        };

        match outcome {
            DriverEvent::Drain => {
                info!(%id, "session draining (server shutdown)");
                acct_cause.set(crate::auth::accounting::SessionEnd::NasReboot);
                let out = ssm.on_higher_layer_disconnect(&mut tx_buf);
                if !handle_sstp_step(
                    id,
                    &mut tx,
                    &out,
                    &mut tx_buf,
                    &mut sstp_timer,
                    &mut ppp,
                    &mut ppp_timer,
                    &auth,
                    local_ip,
                    auth_method,
                    &mut kppp,
                    data_path,
                    &mut pending_shaping,
                    &mut pending_policy,
                    &mut pending_username,
                    &mut pending_hlak,
                    &mut acct_state,
                    mss_table,
                    &mut mss_handle,
                    &info,
                )
                .await
                {
                    return;
                }
            }
            DriverEvent::Control(Some(ControlCommand::Disconnect(reason))) => {
                info!(%id, ?reason, "session control: disconnect");
                acct_cause.set(crate::auth::accounting::SessionEnd::from(reason));
                let out = ssm.on_higher_layer_disconnect(&mut tx_buf);
                if !handle_sstp_step(
                    id,
                    &mut tx,
                    &out,
                    &mut tx_buf,
                    &mut sstp_timer,
                    &mut ppp,
                    &mut ppp_timer,
                    &auth,
                    local_ip,
                    auth_method,
                    &mut kppp,
                    data_path,
                    &mut pending_shaping,
                    &mut pending_policy,
                    &mut pending_username,
                    &mut pending_hlak,
                    &mut acct_state,
                    mss_table,
                    &mut mss_handle,
                    &info,
                )
                .await
                {
                    return;
                }
            }
            DriverEvent::Control(Some(ControlCommand::PeriodicTick)) => {
                // --- Hello keepalive check ---
                use crate::sstp::state::{State, TIMER_VAL_HELLO};
                if ssm.state() == State::ServerCallConnected {
                    let idle = last_rx.elapsed();
                    if hello_echo_pending && idle >= TIMER_VAL_HELLO + TIMER_VAL_HELLO {
                        debug!(%id, ?idle, "hello timeout: no echo response, aborting");
                        let out = ssm.on_hello_timeout_no_response();
                        if !handle_sstp_step(
                            id,
                            &mut tx,
                            &out,
                            &mut tx_buf,
                            &mut sstp_timer,
                            &mut ppp,
                            &mut ppp_timer,
                            &auth,
                            local_ip,
                            auth_method,
                            &mut kppp,
                            data_path,
                            &mut pending_shaping,
                            &mut pending_policy,
                            &mut pending_username,
                            &mut pending_hlak,
                            &mut acct_state,
                            mss_table,
                            &mut mss_handle,
                            &info,
                        )
                        .await
                        {
                            return;
                        }
                    } else if !hello_echo_pending && idle >= TIMER_VAL_HELLO {
                        debug!(%id, ?idle, "hello: sending echo request");
                        hello_echo_pending = true;
                        let out = ssm.on_timer(Timer::Hello, &mut tx_buf);
                        if !handle_sstp_step(
                            id,
                            &mut tx,
                            &out,
                            &mut tx_buf,
                            &mut sstp_timer,
                            &mut ppp,
                            &mut ppp_timer,
                            &auth,
                            local_ip,
                            auth_method,
                            &mut kppp,
                            data_path,
                            &mut pending_shaping,
                            &mut pending_policy,
                            &mut pending_username,
                            &mut pending_hlak,
                            &mut acct_state,
                            mss_table,
                            &mut mss_handle,
                            &info,
                        )
                        .await
                        {
                            return;
                        }
                    }
                }

                // --- Accounting interim check ---
                if last_acct_interim.elapsed() >= acct_interim_period {
                    last_acct_interim = Instant::now();
                    if let (Some(state), Some(bridge)) = (acct_state.as_mut(), auth.acct) {
                        let counters = sample_acct_counters(
                            state.ifindex,
                            state.started,
                            &state.last_counters,
                        );
                        let total = counters.input_octets.saturating_add(counters.output_octets);
                        if total != last_activity_octets {
                            last_activity_octets = total;
                            if let Some(period) = idle_timeout {
                                idle_timeout_deadline = Some(Box::pin(tokio::time::sleep(period)));
                            }
                        }
                        state.last_counters = counters.clone();
                        bridge.submit(
                            state.username.clone(),
                            peer,
                            state.session.clone(),
                            crate::auth::accounting::AcctEvent::InterimUpdate,
                            counters,
                        );
                    }
                }
            }
            DriverEvent::Control(Some(ControlCommand::Rekey { request_peer })) => {
                // Operator-initiated TLS 1.3 KeyUpdate. Only meaningful
                // on the TUN backend: the kmod owns the kTLS record
                // layer post-attach, so libssl can no longer drive the
                // socket. Cooperative rekey across the kmod boundary
                // (SSTP_IOC_REKEY_TX/RX) is not implemented — matches
                // HAProxy's AWS-LC + kTLS posture, see
                // crate::crypto::rekey.
                let backend_is_kernel = kppp.as_ref().is_some_and(KpppSession::is_kernel);
                if backend_is_kernel {
                    warn!(
                        %id,
                        "session control: rekey rejected (kmod backend has no cooperative-rekey path; reconnect to rotate keys)"
                    );
                } else {
                    match tx.tls.request_key_update(request_peer) {
                        Ok(()) => {
                            info!(
                                %id,
                                request_peer,
                                "session control: TLS 1.3 KeyUpdate queued (sent on next write)"
                            );
                        }
                        Err(e) => {
                            warn!(%id, error = %e, "session control: rekey failed");
                        }
                    }
                }
            }
            DriverEvent::Control(None) => {
                debug!(%id, "control channel closed by all senders");
                return;
            }
            DriverEvent::SessionTimeout => {
                info!(%id, "Session-Timeout reached; tearing session down");
                acct_cause.set(crate::auth::accounting::SessionEnd::SessionTimeout);
                return;
            }
            DriverEvent::IdleTimeout => {
                info!(%id, "Idle-Timeout reached; tearing session down");
                acct_cause.set(crate::auth::accounting::SessionEnd::IdleTimeout);
                return;
            }
            DriverEvent::SstpTimer => {
                let (which, _) = sstp_timer
                    .take()
                    .expect("sstp timer slot is Some when timer fires");
                debug!(%id, ?which, "SSTP timer expired");
                let out = ssm.on_timer(which, &mut tx_buf);
                if !handle_sstp_step(
                    id,
                    &mut tx,
                    &out,
                    &mut tx_buf,
                    &mut sstp_timer,
                    &mut ppp,
                    &mut ppp_timer,
                    &auth,
                    local_ip,
                    auth_method,
                    &mut kppp,
                    data_path,
                    &mut pending_shaping,
                    &mut pending_policy,
                    &mut pending_username,
                    &mut pending_hlak,
                    &mut acct_state,
                    mss_table,
                    &mut mss_handle,
                    &info,
                )
                .await
                {
                    return;
                }
            }
            DriverEvent::PppTimer => {
                let (owner, _) = ppp_timer
                    .take()
                    .expect("ppp timer slot is Some when timer fires");
                debug!(%id, ?owner, "PPP timer expired");
                if let Some(p) = ppp.as_mut() {
                    let step = p.on_timer(owner);
                    if !handle_ppp_step(
                        id,
                        &mut tx,
                        &mut tx_buf,
                        p,
                        step,
                        &mut ppp_timer,
                        &auth,
                        local_ip,
                        auth_method,
                        &mut kppp,
                        data_path,
                        &mut pending_shaping,
                        &mut pending_policy,
                        &mut pending_username,
                        &mut pending_hlak,
                        &mut acct_state,
                        mss_table,
                        &mut mss_handle,
                        &info,
                    )
                    .await
                    {
                        return;
                    }
                }
            }
            DriverEvent::KpppRead(Err(e)) => {
                // Transient read error on the kernel unit fd; log and
                // keep going. A persistent failure will fall out via
                // the next TLS write or session teardown.
                warn!(%id, error = %e, "kernel PPP unit read failed");
            }
            DriverEvent::KpppRead(Ok(0)) => {
                // Only the TUN backend feeds this branch (kernel
                // mode never resolves `read_frame`). EOF means the
                // tun fd was closed out from under us — tear down.
                warn!(%id, "tun fd returned EOF; tearing down session");
                return;
            }
            DriverEvent::KpppRead(Ok(n)) => {
                if let Err(e) = write_ppp_as_sstp_data(&mut tx, &mut tx_buf, &kppp_buf[..n]).await {
                    warn!(%id, error = %e, "TLS write of kernel-PPP frame failed");
                    return;
                }
                if let Err(e) = tx.flush().await {
                    warn!(%id, error = %e, "TLS flush after kernel-PPP frame failed");
                    return;
                }
            }
            DriverEvent::KmodEvents { io_err } => {
                // Kmod control events count as rx activity for hello.
                last_rx = Instant::now();
                hello_echo_pending = false;

                if let Some(e) = io_err {
                    warn!(%id, error = %e, "kmod event poll failed; tearing session down");
                    return;
                }
                // `kmod_events` was populated by the select arm
                // body and stays alive across this match (the
                // `clear()` happens at the *next* wakeup).
                // `EventRaw: Copy` so `.copied()` lifts each one
                // out and the body holds no borrow on the Vec.
                for ev in kmod_events.iter().copied() {
                    match EventType::from_u32(ev.r#type) {
                        Some(EventType::ControlPacket) => {
                            let n = match kppp
                                .as_ref()
                                .expect("kmod event without KpppSession")
                                .recv_control(&mut ctrl_buf)
                            {
                                Ok(Some(n)) => n,
                                Ok(None) => continue, // raced with another drain
                                Err(e) => {
                                    warn!(%id, error = %e, "SSTP_IOC_RECV_CONTROL failed");
                                    return;
                                }
                            };
                            let payload = &ctrl_buf[..n];
                            let msg = match parse_control_payload(payload) {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!(%id, error = %e, "kmod control packet parse failed");
                                    return;
                                }
                            };
                            let out = match msg {
                                // CallConnected's Crypto-Binding HMAC
                                // is computed over the full 112-byte
                                // packet (header included) with the
                                // Compound MAC field at [80..112]
                                // zeroed ([MS-SSTP] §3.2.5.2.3). The
                                // kmod stripped the 4-byte header, so
                                // reconstruct it.
                                ControlMessage::CallConnected(cb) => {
                                    if payload.len() + SSTP_HEADER_LEN != CALL_CONNECTED_LEN {
                                        warn!(
                                            %id,
                                            got = payload.len() + SSTP_HEADER_LEN,
                                            want = CALL_CONNECTED_LEN,
                                            "CallConnected wrong length"
                                        );
                                        return;
                                    }
                                    let mut zeroed = [0u8; CALL_CONNECTED_LEN];
                                    let (hdr, body) = zeroed.split_at_mut(SSTP_HEADER_LEN);
                                    let hdr: &mut [u8; SSTP_HEADER_LEN] =
                                        hdr.try_into().expect("SSTP_HEADER_LEN slice");
                                    write_header(hdr, true, CALL_CONNECTED_LEN);
                                    body.copy_from_slice(payload);
                                    zeroed[80..112].fill(0);
                                    ssm.verify_call_connected(cb, &zeroed, &mut tx_buf)
                                }
                                other => ssm.on_message(other, &mut tx_buf),
                            };
                            if !handle_sstp_step(
                                id,
                                &mut tx,
                                &out,
                                &mut tx_buf,
                                &mut sstp_timer,
                                &mut ppp,
                                &mut ppp_timer,
                                &auth,
                                local_ip,
                                auth_method,
                                &mut kppp,
                                data_path,
                                &mut pending_shaping,
                                &mut pending_policy,
                                &mut pending_username,
                                &mut pending_hlak,
                                &mut acct_state,
                                mss_table,
                                &mut mss_handle,
                                &info,
                            )
                            .await
                            {
                                return;
                            }
                        }
                        Some(EventType::PeerClosed) => {
                            info!(%id, "kmod: peer closed TCP connection");
                            return;
                        }
                        Some(EventType::TlsFatalAlert) => {
                            warn!(%id, alert = ev.arg, "kmod: TLS fatal alert");
                            return;
                        }
                        Some(EventType::ProtocolError) => {
                            warn!(%id, code = ev.arg, "kmod: SSTP protocol error");
                            return;
                        }
                        Some(EventType::TlsRekeyNeeded) => {
                            // TLS 1.3 post-handshake record on the kmod
                            // data path. The kmod surfaces the TLS
                            // content type byte (RFC 8446 §B.1) in
                            // `ev.arg`; we classify it via the pure
                            // rekey FSM and tear down. Cooperative
                            // resume across a `KeyUpdate` is not
                            // implemented (REKEY_TX/REKEY_RX are
                            // -ENOSYS and not planned for v0.x —
                            // matches HAProxy's AWS-LC posture, see
                            // crate::crypto::rekey).
                            // Server-side ticket emission is disabled
                            // at SSL_CTX init (see crypto::tls), so a
                            // handshake record here is overwhelmingly
                            // a client-initiated `KeyUpdate` —
                            // Windows/sstpc don't send them in
                            // practice, so the counter exists mainly
                            // to flag exotic peers.
                            let ct = crypto::rekey::TlsContentType::from_u8((ev.arg & 0xff) as u8);
                            let action = crypto::rekey::decide_v03_kmod(ct);
                            match ct {
                                crypto::rekey::TlsContentType::Handshake => {
                                    metrics::SESSION_TEARDOWN_REKEY_HANDSHAKE.inc();
                                }
                                crypto::rekey::TlsContentType::Alert => {
                                    metrics::SESSION_TEARDOWN_REKEY_ALERT.inc();
                                }
                                _ => {
                                    metrics::SESSION_TEARDOWN_REKEY_OTHER.inc();
                                }
                            }
                            let reason = match action {
                                crypto::rekey::Action::TearDown { reason } => reason.label(),
                                _ => "unexpected_action",
                            };
                            info!(
                                %id,
                                record_type = ct.label(),
                                content_type = ev.arg,
                                reason,
                                "kmod: TLS post-handshake record (rekey not yet supported); tearing down"
                            );
                            return;
                        }
                        None => {
                            warn!(%id, ty = ev.r#type, "kmod: unknown event type");
                        }
                    }
                }
            }
            DriverEvent::Read(Ok(0)) => {
                info!(%id, "peer closed connection");
                return;
            }
            DriverEvent::Read(Err(e)) => {
                warn!(%id, error = %e, "TLS read failed");
                return;
            }
            DriverEvent::Read(Ok(n)) => {
                // Any inbound byte activity resets the hello state.
                last_rx = Instant::now();
                hello_echo_pending = false;

                rx_buf.extend_from_slice(&chunk[..n]);
                // Drain as many complete SSTP packets as the buffer
                // currently holds. The codec is zero-copy against
                // the borrowed slice; we track a cursor and compact
                // once at the end of the branch (saves N-1
                // `memmove`s when one read carries multiple
                // packets).
                let mut read_pos: usize = 0;
                loop {
                    let parsed = Packet::parse(&rx_buf[read_pos..]);
                    let consumed = match parsed {
                        Err(
                            crate::sstp::ParseError::Truncated
                            | crate::sstp::ParseError::LengthMismatch { .. },
                        ) => break,
                        Err(e) => {
                            warn!(%id, error = %e, "SSTP frame parse failed; aborting");
                            return;
                        }
                        Ok((Packet::Data(payload), length)) => {
                            // Data packets restart the hello timer
                            // once SSTP is `Server_Call_Connected`,
                            // and (when PPP is running) feed into the
                            // PPP demux — except for IP frames once
                            // the kernel PPP unit is up, which are
                            // written straight to the unit fd.
                            let out = ssm.on_data_packet();
                            if !handle_sstp_step(
                                id,
                                &mut tx,
                                &out,
                                &mut tx_buf,
                                &mut sstp_timer,
                                &mut ppp,
                                &mut ppp_timer,
                                &auth,
                                local_ip,
                                auth_method,
                                &mut kppp,
                                data_path,
                                &mut pending_shaping,
                                &mut pending_policy,
                                &mut pending_username,
                                &mut pending_hlak,
                                &mut acct_state,
                                mss_table,
                                &mut mss_handle,
                                &info,
                            )
                            .await
                            {
                                return;
                            }
                            let mut routed_to_kernel = false;
                            // NP-mode filter ([RFC 1661] §3.2; mirrors
                            // `ppp_generic`'s `PPPIOCSNPMODE` on the
                            // kmod path). Network-layer frames are
                            // dropped pre-IPCP / oversized; control
                            // protocols fall through to the in-process
                            // PPP FSM. Kernel-mode kmod owns the byte
                            // path so Data packets shouldn't surface
                            // here at all — if one does, treat it as
                            // a programming error and drop.
                            if let Ok(frame) = crate::ppp::frame::decode_frame(payload) {
                                let network_ready = kppp.as_ref().is_some_and(|k| !k.is_kernel());
                                let mtu = kppp.as_ref().map_or(0, KpppSession::mtu);
                                let info_len = frame.info.len();
                                match np_filter_decide(network_ready, mtu, frame.protocol, info_len)
                                {
                                    NpFilter::Forward => {
                                        // `network_ready` true => `kppp` is
                                        // `Some` and not kernel-mode.
                                        let k = kppp
                                            .as_ref()
                                            .expect("np_filter Forward implies kppp.is_some()");
                                        if let Err(e) = k.write_ip_body(frame.info).await {
                                            warn!(
                                                %id,
                                                error = %e,
                                                "kernel PPP unit write failed",
                                            );
                                        }
                                        routed_to_kernel = true;
                                    }
                                    NpFilter::DropPreIpcp => {
                                        metrics::NP_FILTER_DROPS_PRE_IPCP.inc();
                                        debug!(
                                            %id,
                                            protocol = format_args!("0x{:04x}", frame.protocol),
                                            len = info_len,
                                            "NP filter: dropping pre-IPCP network-layer frame",
                                        );
                                        routed_to_kernel = true;
                                    }
                                    NpFilter::DropMruExceeded => {
                                        metrics::NP_FILTER_DROPS_MRU.inc();
                                        debug!(
                                            %id,
                                            protocol = format_args!("0x{:04x}", frame.protocol),
                                            len = info_len,
                                            mtu,
                                            "NP filter: dropping oversized network-layer frame",
                                        );
                                        routed_to_kernel = true;
                                    }
                                    NpFilter::NotNetworkLayer => {
                                        // Fall through to the in-process
                                        // PPP FSM below.
                                    }
                                }
                            }
                            if !routed_to_kernel && let Some(p) = ppp.as_mut() {
                                let step = p.on_frame(payload);
                                if !handle_ppp_step(
                                    id,
                                    &mut tx,
                                    &mut tx_buf,
                                    p,
                                    step,
                                    &mut ppp_timer,
                                    &auth,
                                    local_ip,
                                    auth_method,
                                    &mut kppp,
                                    data_path,
                                    &mut pending_shaping,
                                    &mut pending_policy,
                                    &mut pending_username,
                                    &mut pending_hlak,
                                    &mut acct_state,
                                    mss_table,
                                    &mut mss_handle,
                                    &info,
                                )
                                .await
                                {
                                    return;
                                }
                            }
                            length
                        }
                        Ok((Packet::Control(ctrl), length)) => {
                            match parse_control(ctrl) {
                                Ok(msg) => {
                                    let out = match msg {
                                        // Call-Connected carries the Crypto
                                        // Binding the server must verify
                                        // against the raw packet with the
                                        // Compound MAC field zeroed
                                        // ([MS-SSTP] §3.2.5.2.3). The MAC
                                        // sits at offsets 80..112 of the
                                        // 112-byte packet (§2.2.11).
                                        ControlMessage::CallConnected(cb) => {
                                            debug_assert_eq!(length, CALL_CONNECTED_LEN);
                                            let mut zeroed = [0u8; CALL_CONNECTED_LEN];
                                            zeroed.copy_from_slice(
                                                &rx_buf[read_pos..read_pos + CALL_CONNECTED_LEN],
                                            );
                                            zeroed[80..112].fill(0);
                                            ssm.verify_call_connected(cb, &zeroed, &mut tx_buf)
                                        }
                                        other => ssm.on_message(other, &mut tx_buf),
                                    };
                                    if !handle_sstp_step(
                                        id,
                                        &mut tx,
                                        &out,
                                        &mut tx_buf,
                                        &mut sstp_timer,
                                        &mut ppp,
                                        &mut ppp_timer,
                                        &auth,
                                        local_ip,
                                        auth_method,
                                        &mut kppp,
                                        data_path,
                                        &mut pending_shaping,
                                        &mut pending_policy,
                                        &mut pending_username,
                                        &mut pending_hlak,
                                        &mut acct_state,
                                        mss_table,
                                        &mut mss_handle,
                                        &info,
                                    )
                                    .await
                                    {
                                        return;
                                    }
                                }
                                Err(e) => {
                                    warn!(%id, error = %e, "SSTP control parse failed");
                                    return;
                                }
                            }
                            length
                        }
                    };
                    read_pos += consumed;
                }
                // Compact once: if everything was consumed,
                // `clear()` resets `len` to 0 in O(1); otherwise a
                // single `drain` shifts the unparsed tail to slot 0.
                if read_pos == rx_buf.len() {
                    rx_buf.clear();
                } else if read_pos > 0 {
                    rx_buf.drain(..read_pos);
                }
            }
        }
    }
}

/// NP-mode filter outcome for an inbound PPP frame carried inside
/// an SSTP `Data` packet. Computed by [`np_filter_decide`] and
/// applied by [`drive_sstp`].
///
/// Mirrors the semantics of `ppp_generic`'s `PPPIOCSNPMODE` switch
/// ([RFC 1661] §3.2 "Network-Layer Protocol Phase"): network-layer
/// protocols (IPv4 / IPv6) are passed only after IPCP / IPV6CP has
/// converged. On the kmod backend this gating happens in the
/// kernel; on the TUN backend the same check lives here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpFilter {
    /// Frame is not network-layer (LCP / IPCP / PAP / CHAP / EAP /
    /// unknown). Hand to the in-process PPP FSM unchanged.
    NotNetworkLayer,
    /// Network-layer frame, data path is up, body fits the
    /// negotiated MTU. Caller writes the body to `KpppSession`.
    Forward,
    /// Network-layer frame received before the data path was brought
    /// up (i.e. before [`PppEvent::NetworkUp`]). Drop silently and
    /// bump [`metrics::NP_FILTER_DROPS_PRE_IPCP`]. The peer should
    /// not be sending IP traffic before its own IPCP completes; if
    /// it does, we refuse to forward and rely on IPCP to converge.
    DropPreIpcp,
    /// Network-layer frame larger than the negotiated MTU. Drop and
    /// bump [`metrics::NP_FILTER_DROPS_MRU`]. Standard PPP MRU
    /// enforcement ([RFC 1661] §6.1) — `ppp_generic` does this for
    /// us on the kmod path; we replicate it on TUN.
    DropMruExceeded,
}

/// Pure decision function for the NP-mode filter. Inputs:
///
/// - `network_ready`: `true` once the data path (TUN or kmod) is
///   brought up — i.e. `kppp.is_some()` in [`drive_sstp`].
/// - `mtu`: negotiated MTU for the data path. Only consulted when
///   `network_ready` is `true`.
/// - `protocol`: PPP protocol field from the decoded frame.
/// - `info_len`: length of the frame's information field (i.e. the
///   IP packet body that would be written to the data path).
fn np_filter_decide(network_ready: bool, mtu: u32, protocol: u16, info_len: usize) -> NpFilter {
    let Some(p) = crate::ppp::frame::ProtocolId::from_u16(protocol) else {
        return NpFilter::NotNetworkLayer;
    };
    if !p.is_network_layer() {
        return NpFilter::NotNetworkLayer;
    }
    if !network_ready {
        return NpFilter::DropPreIpcp;
    }
    if info_len > mtu as usize {
        return NpFilter::DropMruExceeded;
    }
    NpFilter::Forward
}

/// One-shot description of which select arm fired. Kept local to
/// [`drive_sstp`] because it has no other consumers.
enum DriverEvent {
    Drain,
    Control(Option<ControlCommand>),
    SstpTimer,
    PppTimer,
    KpppRead(std::io::Result<usize>),
    /// `Session-Timeout` (RFC 2865 §5.27) hard deadline expired —
    /// tear down with `Acct-Terminate-Cause=Session-Timeout`.
    SessionTimeout,
    /// `Idle-Timeout` (RFC 2865 §5.28) elapsed without any
    /// rx/tx octet counter movement — tear down with
    /// `Acct-Terminate-Cause=Idle-Timeout`.
    IdleTimeout,
    /// Kmod session fd became readable; the select arm body has
    /// already drained all queued events into `kmod_events` and
    /// cleared readiness on the guard.
    KmodEvents {
        io_err: Option<std::io::Error>,
    },
    Read(std::io::Result<usize>),
}

/// Apply an SSTP [`StepOut`] via [`apply_step`], then handle any
/// `NotifyHigher` that resulted by spinning up the PPP driver
/// (`StartPpp`) or logging (`SstpEstablished`). Returns `false` when
/// the driver should exit.
#[allow(clippy::too_many_arguments)]
async fn handle_sstp_step(
    id: SessionId,
    tx: &mut TxStream,
    out: &crate::sstp::StepOut,
    tx_buf: &mut [u8],
    sstp_timer: &mut Option<(
        crate::sstp::state::Timer,
        std::pin::Pin<Box<tokio::time::Sleep>>,
    )>,
    ppp: &mut Option<Ppp>,
    ppp_timer: &mut Option<(TimerOwner, std::pin::Pin<Box<tokio::time::Sleep>>)>,
    auth: &AuthCtx<'_>,
    local_ip: Ipv4Addr,
    auth_method: AuthMethod,
    kppp: &mut Option<KpppSession>,
    data_path: DataPathMode,
    pending_shaping: &mut Option<crate::shape::ShapingPolicy>,
    pending_policy: &mut Option<crate::auth::SessionPolicy>,
    pending_username: &mut Option<String>,
    pending_hlak: &mut Option<[u8; 32]>,
    acct_state: &mut Option<AcctState>,
    mss_table: Option<&Arc<SharedMssTable>>,
    mss_handle: &mut Option<SharedMssHandle>,
    info: &SessionInfoHandle,
) -> bool {
    let outcome = apply_step(id, tx, out, tx_buf, sstp_timer, kppp.as_ref()).await;
    if !outcome.keep_going {
        return false;
    }
    if outcome.start_ppp {
        if ppp.is_some() {
            debug!(%id, "spurious StartPpp notify after PPP already running");
            return true;
        }
        info!(%id, "starting PPP control plane");
        let mut new_ppp = Ppp::new(local_ip.octets(), auth_method);
        let step = new_ppp.open();
        *ppp = Some(new_ppp);
        if !handle_ppp_step(
            id,
            tx,
            tx_buf,
            ppp.as_mut().expect("just inserted"),
            step,
            ppp_timer,
            auth,
            local_ip,
            auth_method,
            kppp,
            data_path,
            pending_shaping,
            pending_policy,
            pending_username,
            pending_hlak,
            acct_state,
            mss_table,
            mss_handle,
            info,
        )
        .await
        {
            return false;
        }
    }
    true
}

/// Publish RADIUS Access-Accept results into the session info block
/// for `show session`. Cheap mutex lock; never on the data path.
fn publish_auth_accept(info: &SessionInfoHandle, user: &str, assigned_ip: Ipv4Addr) {
    let mut g = info.lock().expect("session info mutex poisoned");
    g.username = Some(user.to_string());
    g.assigned_ip = Some(assigned_ip);
}

/// Publish kernel-PPP / TUN bring-up parameters into the session
/// info block for `show session`.
fn publish_data_path(
    info: &SessionInfoHandle,
    ifname: String,
    mtu: u32,
    backend: &'static str,
    shaping: Option<&crate::shape::ShapingPolicy>,
) {
    let mut g = info.lock().expect("session info mutex poisoned");
    g.ifname = Some(ifname);
    g.mtu = Some(mtu);
    g.backend = Some(backend);
    g.shaping = shaping.copied();
}

/// Apply a [`PppStep`]: write each frame as an SSTP data packet,
/// update the PPP timer slot, and act on any [`PppEvent`]. PAP
/// credentials are dispatched to the [`AuthBridge`] (M6e); the
/// returned verdict is fed back into the PPP driver via
/// [`Ppp::on_auth_result`], which produces the next [`PppStep`]
/// (PAP-Ack/-Nak plus, on accept, IPCP `Configure-Request`).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // straight-line event handling in one place for state clarity
async fn handle_ppp_step(
    id: SessionId,
    tx: &mut TxStream,
    tx_buf: &mut [u8],
    ppp: &mut Ppp,
    mut step: PppStep,
    ppp_timer: &mut Option<(TimerOwner, std::pin::Pin<Box<tokio::time::Sleep>>)>,
    auth: &AuthCtx<'_>,
    local_ip: Ipv4Addr,
    _auth_method: AuthMethod,
    kppp: &mut Option<KpppSession>,
    data_path: DataPathMode,
    pending_shaping: &mut Option<crate::shape::ShapingPolicy>,
    pending_policy: &mut Option<crate::auth::SessionPolicy>,
    pending_username: &mut Option<String>,
    pending_hlak: &mut Option<[u8; 32]>,
    acct_state: &mut Option<AcctState>,
    mss_table: Option<&Arc<SharedMssTable>>,
    mss_handle: &mut Option<SharedMssHandle>,
    info: &SessionInfoHandle,
) -> bool {
    use tokio::time::{Instant, sleep_until};

    // Loop because handling an event (e.g. PAP auth result) re-enters
    // the driver and may produce more frames and another event.
    loop {
        for frame in &step.frames {
            if let Err(e) = write_ppp_as_sstp_data(tx, tx_buf, frame).await {
                warn!(%id, error = %e, "TLS write of PPP frame failed");
                return false;
            }
        }
        if !step.frames.is_empty()
            && let Err(e) = tx.flush().await
        {
            warn!(%id, error = %e, "TLS flush failed");
            return false;
        }
        for owner in &step.timer_stops {
            if ppp_timer.as_ref().is_some_and(|(o, _)| o == owner) {
                *ppp_timer = None;
            }
        }
        for (owner, dur) in &step.timer_starts {
            let deadline = Instant::now() + *dur;
            match ppp_timer.as_mut() {
                Some((slot_owner, sleep)) => {
                    *slot_owner = *owner;
                    sleep.as_mut().reset(deadline);
                }
                None => {
                    *ppp_timer = Some((*owner, Box::pin(sleep_until(deadline))));
                }
            }
        }

        let event = step.event.take();
        let finished = step.finished;

        match event {
            Some(PppEvent::NeedPapAuth { peer_id, password }) => {
                let user = String::from_utf8_lossy(&peer_id).into_owned();
                info!(%id, user = %user, "PAP credentials received; dispatching to RADIUS");
                let outcome = auth
                    .bridge
                    .submit_pap(user.clone(), password, auth.peer)
                    .await;
                let crate::auth::bridge::PapOutcome {
                    verdict,
                    shaping,
                    policy,
                } = outcome;
                match &verdict {
                    AuthVerdict::Accept { addrs } => {
                        info!(%id, user = %user, ip = ?addrs.ip, shaping = ?shaping, "RADIUS Access-Accept");
                        // Stash the shaping policy until the kernel
                        // PPP unit is up; applied alongside
                        // bring-up at `NetworkUp` below.
                        *pending_shaping = shaping;
                        *pending_policy = Some(policy);
                        // Captured for accounting; finalized into
                        // an `AcctState` once the netdev is up.
                        *pending_username = Some(user.clone());
                        publish_auth_accept(info, &user, addrs.ip.into());
                    }
                    AuthVerdict::Reject { message } => {
                        let msg = String::from_utf8_lossy(message);
                        info!(%id, user = %user, reason = %msg, "RADIUS Access-Reject");
                    }
                }
                step = ppp.on_auth_result(verdict);
                // Loop to render the new step.
                continue;
            }
            Some(PppEvent::NeedChapAuth {
                username,
                chap_id,
                challenge,
                response,
            }) => {
                let user = String::from_utf8_lossy(&username).into_owned();
                info!(%id, user = %user, chap_id, "CHAP-MD5 response received; dispatching to RADIUS");
                let outcome = auth
                    .bridge
                    .submit_chap(user.clone(), chap_id, response, challenge, auth.peer)
                    .await;
                let crate::auth::bridge::ChapOutcome {
                    verdict,
                    shaping,
                    policy,
                } = outcome;
                match &verdict {
                    AuthVerdict::Accept { addrs } => {
                        info!(%id, user = %user, ip = ?addrs.ip, shaping = ?shaping, "RADIUS Access-Accept (CHAP)");
                        *pending_shaping = shaping;
                        *pending_policy = Some(policy);
                        *pending_username = Some(user.clone());
                        publish_auth_accept(info, &user, addrs.ip.into());
                    }
                    AuthVerdict::Reject { message } => {
                        let msg = String::from_utf8_lossy(message);
                        info!(%id, user = %user, reason = %msg, "RADIUS Access-Reject (CHAP)");
                    }
                }
                step = ppp.on_auth_result(verdict);
                continue;
            }
            Some(PppEvent::NeedMsChapV2Auth {
                username,
                chap_id,
                authenticator_challenge,
                peer_challenge,
                nt_response,
                flags,
            }) => {
                let user = String::from_utf8_lossy(&username).into_owned();
                info!(%id, user = %user, chap_id, "MS-CHAPv2 response received; dispatching to RADIUS");
                let outcome = auth
                    .bridge
                    .submit_mschapv2(
                        user.clone(),
                        chap_id,
                        authenticator_challenge,
                        peer_challenge,
                        nt_response,
                        flags,
                        auth.peer,
                    )
                    .await;
                let crate::auth::bridge::MsChapOutcome {
                    verdict,
                    shaping,
                    policy,
                    auth_response,
                    error_string,
                    hlak,
                } = outcome;
                match &verdict {
                    AuthVerdict::Accept { addrs } => {
                        info!(
                            %id,
                            user = %user,
                            ip = ?addrs.ip,
                            shaping = ?shaping,
                            hlak_present = hlak.is_some(),
                            "RADIUS Access-Accept (MS-CHAPv2)"
                        );
                        *pending_shaping = shaping;
                        *pending_policy = Some(policy);
                        *pending_username = Some(user.clone());
                        publish_auth_accept(info, &user, addrs.ip.into());
                        // Crypto Binding HLAK ([MS-SSTP] §3.2.5.2.2):
                        // captured here, applied by `drive_sstp` via
                        // `ssm.on_inner_auth_completed` once this
                        // handler returns. `None` falls through to
                        // ServerBypassHLAuth (zero HLAK), which
                        // Windows clients reject — already warned in
                        // the bridge.
                        *pending_hlak = hlak;
                    }
                    AuthVerdict::Reject { message } => {
                        let msg = String::from_utf8_lossy(message);
                        info!(%id, user = %user, reason = %msg, "RADIUS Access-Reject (MS-CHAPv2)");
                    }
                }
                step = ppp.on_mschap_result(
                    verdict,
                    auth_response.as_deref(),
                    error_string.as_deref(),
                );
                continue;
            }
            Some(PppEvent::NetworkUp(addrs)) => {
                let peer_ip = Ipv4Addr::from(addrs.ip);
                let link_mtu = addrs.mtu.map(u32::from);
                tracing::trace!(
                    target: "sstp::mtu",
                    %id,
                    %peer_ip,
                    link_mtu = ?link_mtu,
                    "NetworkUp: handing peer IP + MTU to KpppSession::bring_up"
                );
                if kppp.is_some() {
                    debug!(%id, ip = %peer_ip, "spurious NetworkUp after kernel PPP unit already attached");
                } else {
                    let ktls = tx.tls.ktls_eligibility();
                    // Resolve Auto definitively at session time based on
                    // the negotiated cipher: kTLS-compatible sessions
                    // escalate to Kernel (kmod presence was already
                    // confirmed at boot, see main::resolve_data_path_mode);
                    // incompatible ones fall back to TUN. Once kTLS is
                    // installed there is no rollback path — the TLS
                    // socket is in `tls` ULP mode and libssl can no
                    // longer encrypt/decrypt — so the decision must be
                    // final before `install_ktls` runs.
                    let mut effective_data_path = match data_path {
                        DataPathMode::Auto => {
                            if ktls.compatible {
                                DataPathMode::Kernel
                            } else {
                                info!(
                                    %id,
                                    tls_version = %ktls.tls_version,
                                    cipher = %ktls.cipher,
                                    "kTLS-incompatible TLS session; falling back to TUN data path"
                                );
                                DataPathMode::Tun
                            }
                        }
                        m => m,
                    };
                    if matches!(data_path, DataPathMode::Kernel) && !ktls.compatible {
                        warn!(
                            %id,
                            tls_version = %ktls.tls_version,
                            cipher = %ktls.cipher,
                            "kernel data path forced by config, but negotiated TLS session is outside v0.1 kTLS allow-list"
                        );
                    }

                    // Install kTLS on the TCP socket before the
                    // kmod attach when kernel mode is in play. The
                    // kmod's `SSTP_IOC_ATTACH` requires kTLS RX+TX
                    // to be installed up-front (it returns
                    // `EOPNOTSUPP` otherwise). After install,
                    // the kmod owns the data-plane byte path;
                    // control frames go through
                    // `SSTP_IOC_SEND_CONTROL`, which the kmod
                    // sends via kTLS on our behalf. Under
                    // `--data-path auto` we skip the install
                    // entirely so the TUN-fallback path keeps
                    // using libssl as before.
                    if matches!(effective_data_path, DataPathMode::Kernel) && ktls.compatible {
                        if let Err(e) = tx.tls.install_ktls() {
                            // `BufferedData` is a transient, timing-
                            // dependent condition (e.g. the client's
                            // first IP packet coalesced into the final
                            // IPCP segment), not a structural failure.
                            // Under `auto` we downgrade to the TUN data
                            // path so libssl reads the buffered bytes
                            // correctly and the session survives; under
                            // forced `kernel` there is no fallback, so
                            // it stays fatal. Every other install error
                            // is fatal regardless of mode.
                            if let (
                                crate::crypto::tls::TlsError::BufferedData(n),
                                DataPathMode::Auto,
                            ) = (&e, data_path)
                            {
                                info!(
                                    %id,
                                    buffered = *n,
                                    "libssl held buffered data at kTLS install; falling back to TUN data path"
                                );
                                effective_data_path = DataPathMode::Tun;
                            } else {
                                warn!(%id, error = %e, "kTLS install failed; cannot bring up kernel data path");
                                return false;
                            }
                        } else {
                            info!(
                                %id,
                                tls_version = %ktls.tls_version,
                                cipher = %ktls.cipher,
                                "kTLS installed on TCP socket"
                            );
                        }
                    }

                    match KpppSession::bring_up(
                        effective_data_path,
                        tx.tls.tcp_fd(),
                        local_ip,
                        peer_ip,
                        link_mtu,
                    ) {
                        Ok(k) => {
                            let backend = if k.is_kernel() { "kmod" } else { "tun" };
                            info!(
                                %id,
                                ifname = %k.ifname(),
                                ifindex = k.ifindex(),
                                local = %local_ip,
                                peer = %peer_ip,
                                tls_version = %ktls.tls_version,
                                cipher = %ktls.cipher,
                                kernel_path = k.is_kernel(),
                                backend,
                                "data path ready"
                            );
                            publish_data_path(
                                info,
                                k.ifname(),
                                k.mtu(),
                                backend,
                                pending_shaping.as_ref(),
                            );
                            // Apply RADIUS-driven traffic shaping
                            // (Mikrotik-Rate-Limit VSA, today) on
                            // the freshly-brought-up netdev. Failure
                            // is non-fatal: the session continues
                            // unshaped and a warning is emitted so
                            // the operator can see why a deployment
                            // expecting rate caps isn't getting them.
                            if let Some(policy) = pending_shaping.take() {
                                match crate::shape::Shaper::open() {
                                    Ok(mut shaper) => {
                                        if let Err(e) = shaper.apply(k.ifindex(), &policy) {
                                            warn!(
                                                %id,
                                                ifindex = k.ifindex(),
                                                error = %e,
                                                "shape::apply failed; session continues unshaped"
                                            );
                                        } else {
                                            info!(
                                                %id,
                                                ifindex = k.ifindex(),
                                                ?policy,
                                                "traffic shaping policy applied"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            %id,
                                            error = %e,
                                            "shape::open failed; session continues unshaped"
                                        );
                                    }
                                }
                            }
                            if let Some(table) = mss_table {
                                let mtu = link_mtu.unwrap_or(1500);
                                // Cipher-aware MSS: selects the
                                // shared chain/set the interface
                                // joins based on the negotiated
                                // TLS cipher overhead.
                                let bounds = crate::shape::mss::compute_mss4(
                                    mtu,
                                    &ktls.tls_version,
                                    &ktls.cipher,
                                );
                                let ifname = k.ifname();
                                match table.add(&ifname, bounds.mss4) {
                                    Ok(guard) => {
                                        info!(
                                            %id,
                                            ifname = %ifname,
                                            mtu,
                                            mss = bounds.mss4,
                                            "installed nftables MSS clamp rules"
                                        );
                                        *mss_handle =
                                            Some(SharedMssHandle::new(Arc::clone(table), guard));
                                    }
                                    Err(e) => {
                                        warn!(
                                            %id,
                                            ifname = %ifname,
                                            mtu,
                                            mss = bounds.mss4,
                                            error = %e,
                                            "MSS clamp install failed; session continues without SYN rewrite"
                                        );
                                    }
                                }
                            }
                            // Apply RADIUS-driven `Framed-Route`
                            // entries (RFC 2865 §5.22). Each becomes
                            // a server-side kernel route through
                            // `pppN`, so packets destined for the
                            // LAN behind the client are forwarded
                            // down the tunnel. Failures are logged
                            // and the session continues — partial
                            // routing is better than no session.
                            // Routes are auto-removed when `pppN`
                            // disappears, so no explicit teardown.
                            if let Some(policy) = pending_policy.as_ref()
                                && !policy.framed_routes.is_empty()
                            {
                                match crate::kppp::netlink::RtNetlink::open() {
                                    Ok(mut rt) => {
                                        for route in &policy.framed_routes {
                                            match rt.add_route(
                                                k.ifindex(),
                                                route.dest,
                                                route.prefix,
                                                route.gateway,
                                                route.metric,
                                            ) {
                                                Ok(()) => {
                                                    info!(
                                                        %id,
                                                        ifindex = k.ifindex(),
                                                        dest = %route.dest,
                                                        prefix = route.prefix,
                                                        gateway = ?route.gateway,
                                                        metric = ?route.metric,
                                                        "Framed-Route installed"
                                                    );
                                                }
                                                Err(e) => {
                                                    warn!(
                                                        %id,
                                                        ifindex = k.ifindex(),
                                                        dest = %route.dest,
                                                        prefix = route.prefix,
                                                        error = %e,
                                                        "Framed-Route install failed; route skipped"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            %id,
                                            error = %e,
                                            "RtNetlink::open failed; Framed-Route entries skipped"
                                        );
                                    }
                                }
                            }
                            *kppp = Some(k);

                            // Finalize accounting state and emit
                            // the Start record. Skipped silently
                            // when no `--acct` server is configured
                            // or when no auth phase ran (anonymous
                            // negotiation paths, currently
                            // unreachable but handled defensively).
                            if let (Some(user), Some(bridge)) = (pending_username.take(), auth.acct)
                            {
                                let kppp_ref = kppp.as_ref().expect("just inserted");
                                let mut session = crate::auth::accounting::AcctSession::new(
                                    peer_ip,
                                    // Acct-Session-Id derives from the
                                    // SessionId; NAS-Port is the low
                                    // 32 bits (RFC 2865 §5.5 only
                                    // requires uniqueness within a
                                    // NAS reboot, and the SessionId
                                    // counter takes ~136 years to
                                    // wrap u32 at 1Hz).
                                    #[allow(clippy::cast_possible_truncation)]
                                    {
                                        id.as_u64() as u32
                                    },
                                );
                                // Echo `Class` from the Access-Accept
                                // (RFC 2865 §5.25) into every
                                // accounting record for Auth↔Acct
                                // correlation.
                                if let Some(p) = pending_policy.as_ref() {
                                    session.class.clone_from(&p.class);
                                }
                                let started = std::time::Instant::now();
                                let counters = crate::auth::accounting::AcctCounters::default();
                                bridge.submit(
                                    user.clone(),
                                    auth.peer,
                                    session.clone(),
                                    crate::auth::accounting::AcctEvent::Start,
                                    counters.clone(),
                                );
                                *acct_state = Some(AcctState {
                                    username: user,
                                    ifindex: kppp_ref.ifindex(),
                                    session,
                                    started,
                                    last_counters: counters,
                                });
                            }
                        }
                        Err(e) => {
                            warn!(%id, error = %e, "kernel PPP unit bring-up failed; tearing session down");
                            return false;
                        }
                    }
                }
            }
            None => {}
        }

        if finished {
            info!(%id, "PPP driver reported finished");
            return false;
        }
        return true;
    }
}

/// Per-session context the PPP driver needs in order to submit auth
/// requests across runtime boundaries. Cheap to construct (one
/// `SocketAddr` copy plus a borrowed [`AuthBridge`] handle) and held
/// only for the duration of [`drive_sstp`].
struct AuthCtx<'a> {
    peer: SocketAddr,
    bridge: &'a AuthBridge,
    /// Optional accounting bridge — `None` when no `--acct` server
    /// is configured. Cloning the whole `AcctBridge` per session
    /// would be cheap (it's just an `mpsc::Sender`) but a borrow
    /// keeps the `AuthCtx` allocation footprint flat.
    acct: Option<&'a AcctBridge>,
}

/// Per-session accounting state, populated once IPCP converges and
/// the kernel netdev is up. Carries everything the dispatcher needs
/// to emit Interim / Stop records without re-deriving it.
///
/// Construction is "all or nothing": if any required input (the
/// authenticated username, framed IP, kernel ifindex) is missing,
/// no `AcctState` is constructed and accounting is silently skipped
/// for the session.
struct AcctState {
    /// `User-Name` from the inbound auth response.
    username: String,
    /// Kernel netdev ifindex (`pppN` or `tun0`) used to sample
    /// `IFLA_STATS64` for Interim/Stop counters.
    ifindex: u32,
    /// Snapshot of the [`AcctSession`] identity attributes
    /// (Acct-Session-Id, Framed-IP-Address, NAS-Port) — immutable
    /// for the session's lifetime.
    session: crate::auth::accounting::AcctSession,
    /// Wall-clock instant of the Start record. Used to compute
    /// `Acct-Session-Time` for subsequent Interim/Stop records.
    started: std::time::Instant,
    /// Last successfully sampled counters, kept so a Stop record
    /// can be emitted with the most recent stats even when the
    /// final netlink sample fails.
    last_counters: crate::auth::accounting::AcctCounters,
}

/// Sample `IFLA_STATS64` for `ifindex` and project to
/// [`AcctCounters`]. Returns the previous best-known counters
/// (passed in as `fallback`) on netlink failure so Interim/Stop
/// records still go out with monotonically-non-decreasing values.
fn sample_acct_counters(
    ifindex: u32,
    started: std::time::Instant,
    fallback: &crate::auth::accounting::AcctCounters,
) -> crate::auth::accounting::AcctCounters {
    use crate::auth::accounting::AcctCounters;
    use crate::kppp::netlink::RtNetlink;
    // `Acct-Session-Time` is a u32 of seconds; 136 years before
    // wrap, so the cast is safe in practice.
    #[allow(clippy::cast_possible_truncation)]
    let session_time = started.elapsed().as_secs() as u32;
    match RtNetlink::open().and_then(|mut nl| nl.link_stats64(ifindex)) {
        Ok(stats) => AcctCounters {
            session_time,
            input_octets: stats.rx_bytes,
            output_octets: stats.tx_bytes,
            // RFC 2866 packet attrs are u32; if a session ever
            // wraps 4G packets (~30 days at 1.5 Mpps line rate)
            // the wrap is silent and matches NAS-vendor practice.
            #[allow(clippy::cast_possible_truncation)]
            input_packets: stats.rx_packets as u32,
            #[allow(clippy::cast_possible_truncation)]
            output_packets: stats.tx_packets as u32,
        },
        Err(e) => {
            warn!(ifindex, error = ?e, "IFLA_STATS64 sample failed; reusing last counters");
            AcctCounters {
                session_time,
                ..*fallback
            }
        }
    }
}

/// RAII Stop emitter: on drop, fires a single
/// [`AcctEvent::Stop`] record for the session if Start has been
/// emitted (i.e. `state` is `Some`). Holds raw pointers into
/// [`drive_sstp`]'s locals; sound because the guard is the
/// last-declared local and therefore drops first while those
/// locals are still alive, and the surrounding task is single-
/// threaded (`!Send`) so there is no aliasing race.
struct AcctStopGuard {
    bridge: Option<*const AcctBridge>,
    /// Pointer to the [`drive_sstp`] local `acct_state`. Read
    /// (via `*mut::take`) only at drop time.
    state_ptr: *mut Option<AcctState>,
    /// Pointer to the [`drive_sstp`] local `acct_cause`. Read
    /// (`Cell::get`) at drop time.
    cause_ptr: *const std::cell::Cell<crate::auth::accounting::SessionEnd>,
    peer: SocketAddr,
}

impl Drop for AcctStopGuard {
    fn drop(&mut self) {
        // SAFETY: the pointers reference locals in `drive_sstp`'s
        // stack frame; this guard is declared after those locals
        // and therefore drops *before* them. The session task is
        // single-threaded (`tokio::task::spawn_local`), so no
        // other code is executing in parallel.
        let state = unsafe { (*self.state_ptr).take() };
        let cause = unsafe { (*self.cause_ptr).get() };
        let Some(state) = state else { return };
        let Some(bridge) = self.bridge else { return };
        // SAFETY: same justification as above; the AcctBridge lives
        // in the caller's stack via the borrowed `acct_bridge` arg.
        let bridge = unsafe { &*bridge };
        let counters = sample_acct_counters(state.ifindex, state.started, &state.last_counters);
        bridge.submit(
            state.username,
            self.peer,
            state.session,
            crate::auth::accounting::AcctEvent::Stop(cause.to_terminate_cause()),
            counters,
        );
    }
}

/// Wrap a raw PPP frame in an SSTP data packet and write it to TLS.
///
/// Coalesces the 4-byte SSTP header and the payload into a single
/// `write_all` so libssl emits one TLS record per data packet (and,
/// in kTLS mode, one `write(2)` syscall) rather than two. The
/// scratch buffer must be at least `SSTP_HEADER_LEN + payload.len()`
/// bytes; callers reuse the per-session `tx_buf` for this.
async fn write_ppp_as_sstp_data(
    tx: &mut TxStream,
    scratch: &mut [u8],
    payload: &[u8],
) -> std::io::Result<()> {
    use crate::sstp::frame::{SSTP_HEADER_LEN, SSTP_MAX_PACKET_LEN, write_header};

    let total = SSTP_HEADER_LEN + payload.len();
    debug_assert!(
        total <= SSTP_MAX_PACKET_LEN,
        "PPP frame exceeds SSTP MTU: {total}"
    );
    debug_assert!(
        scratch.len() >= total,
        "write_ppp_as_sstp_data scratch too small: need {total}, have {}",
        scratch.len()
    );
    let (hdr, body) = scratch[..total].split_at_mut(SSTP_HEADER_LEN);
    let hdr: &mut [u8; SSTP_HEADER_LEN] = hdr.try_into().expect("SSTP_HEADER_LEN slice");
    write_header(hdr, false, total);
    body.copy_from_slice(payload);
    tx.write_all(&scratch[..total]).await
}

/// Apply a [`StepOut`] from the SSTP state machine: write any
/// outbound bytes, update the SSTP timer slot, and decode the
/// terminate flag plus higher-layer notification. Returns
/// [`SstpOutcome`] for the caller to act on (PPP wire-up happens in
/// [`handle_sstp_step`]).
///
/// `kppp` is `Some` once the kernel backend is attached; SSTP
/// control TX then routes through
/// [`KpppSession::send_control`](crate::kppp::session::KpppSession::send_control)
/// so the kmod owns the TLS socket as the sole writer (eliminates
/// userspace-vs-kmod race on TLS records). On the TUN path, or
/// before kernel attach, writes go through [`TxStream::write_all`]
/// as before.
async fn apply_step(
    id: SessionId,
    tx: &mut TxStream,
    out: &crate::sstp::StepOut,
    tx_buf: &[u8],
    active_timer: &mut Option<(
        crate::sstp::state::Timer,
        std::pin::Pin<Box<tokio::time::Sleep>>,
    )>,
    kppp: Option<&KpppSession>,
) -> SstpOutcome {
    use tokio::time::{Instant, sleep_until};

    use crate::sstp::state::{NotifyHigher, Terminate};

    if out.send_len > 0 {
        let kmod_path = kppp.is_some_and(KpppSession::is_kernel);
        tracing::trace!(
            target: "sstp::tx",
            %id,
            len = out.send_len,
            backend = if kmod_path { "kmod" } else { "tls" },
            "SSTP control TX"
        );
        if kmod_path {
            // The SSTP state machine only emits control frames
            // (C=1); every `tx_buf[..send_len]` here is a complete
            // 4-byte-header + body packet. Strip the header and let
            // the kmod prepend its own via SSTP_IOC_SEND_CONTROL.
            debug_assert!(
                out.send_len >= crate::sstp::frame::SSTP_HEADER_LEN,
                "StepOut shorter than SSTP header"
            );
            let body = &tx_buf[crate::sstp::frame::SSTP_HEADER_LEN..out.send_len];
            let kppp_ref = kppp.expect("kmod_path implies kppp.is_some()");
            loop {
                match kppp_ref.send_control(body) {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Wait for TCP writability via the TLS
                        // stream's existing AsyncFd (no dup needed).
                        // The kmod's ioctl backpressure tracks
                        // `sk_stream_is_writeable` on the same socket.
                        match tx.tls.tcp_writable().await {
                            Ok(mut g) => {
                                g.clear_ready();
                            }
                            Err(e) => {
                                warn!(%id, error = %e, "TCP writable wait failed");
                                return SstpOutcome::stop();
                            }
                        }
                    }
                    Err(e) => {
                        warn!(%id, error = %e, "kmod SSTP_IOC_SEND_CONTROL failed");
                        return SstpOutcome::stop();
                    }
                }
            }
        } else {
            if let Err(e) = tx.write_all(&tx_buf[..out.send_len]).await {
                warn!(%id, error = %e, "TLS write failed");
                return SstpOutcome::stop();
            }
            if let Err(e) = tx.flush().await {
                warn!(%id, error = %e, "TLS flush failed");
                return SstpOutcome::stop();
            }
        }
    }

    if let Some(stop) = out.timer_stop
        && active_timer.as_ref().is_some_and(|(t, _)| *t == stop)
    {
        *active_timer = None;
    }
    if let Some((which, dur)) = out.timer_start {
        // Hello keepalive is driven by the per-worker periodic tick
        // (ControlCommand::PeriodicTick); skip arming a per-session
        // Sleep for it. Negotiation / Abort / Disconnect timers
        // still use the per-session slot — they're short-lived and
        // only active during state transitions.
        if which != crate::sstp::state::Timer::Hello {
            let deadline = Instant::now() + dur;
            match active_timer.as_mut() {
                Some((slot_which, sleep)) => {
                    *slot_which = which;
                    sleep.as_mut().reset(deadline);
                }
                None => {
                    *active_timer = Some((which, Box::pin(sleep_until(deadline))));
                }
            }
        }
    }

    let mut start_ppp = false;
    if let Some(note) = out.notify {
        match note {
            NotifyHigher::StartPpp => {
                start_ppp = true;
            }
            NotifyHigher::SstpEstablished => {
                info!(%id, "SSTP: tunnel established, PPP data may flow (M6g)");
            }
        }
    }

    match out.terminate {
        Terminate::None => SstpOutcome {
            keep_going: true,
            start_ppp,
        },
        Terminate::Graceful => {
            info!(%id, "SSTP terminated gracefully");
            SstpOutcome::stop()
        }
        Terminate::Abrupt => {
            info!(%id, "SSTP terminated abruptly");
            SstpOutcome::stop()
        }
    }
}

/// Outbound byte stream for the session driver. Wraps the
/// [`TlsStream`] and, once the SSTP kmod has taken over the data
/// path, an [`AsyncFd`] over a duplicate of the underlying TCP fd.
///
/// Why two paths: kTLS on the TCP socket replaces libssl's
/// record-layer encryption with a kernel-side implementation. After
/// `setsockopt(SOL_TLS, TLS_TX, ...)` libssl no longer encrypts on
/// write, so `SSL_write` would emit double-encrypted gibberish.
/// The fix is to bypass libssl entirely on the write side and use
/// `write(2)` directly on the TCP fd; the kernel does the AEAD.
///
/// The read side stays on `TlsStream` only when the kmod is *not*
/// in charge: once it is, [`drive_sstp`] gates `tls.read` to
/// `Pending` and pulls inbound SSTP control packets out of the
/// kmod's event channel instead.
struct TxStream {
    tls: TlsStream,
}

impl TxStream {
    fn new(tls: TlsStream) -> Self {
        Self { tls }
    }

    /// Write `bytes` to the wire in full via `SSL_write`.
    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.tls.write_all(bytes).await
    }

    /// Drain any libssl buffering.
    async fn flush(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.tls.flush().await
    }
}

/// Outcome of one SSTP FSM step from the session driver's view.
#[derive(Debug, Clone, Copy)]
struct SstpOutcome {
    keep_going: bool,
    start_ppp: bool,
}

impl SstpOutcome {
    fn stop() -> Self {
        Self {
            keep_going: false,
            start_ppp: false,
        }
    }
}

/// RAII guard that unregisters a session on task exit (including
/// panic-unwind). The registry is shared across workers; missing the
/// unregister leaks an entry that the control socket would then
/// surface as a phantom session.
struct RegistrationGuard<'a> {
    registry: &'a Registry,
    id: SessionId,
}

impl Drop for RegistrationGuard<'_> {
    fn drop(&mut self) {
        self.registry.unregister(self.id);
        metrics::CONNECTIONS_ACTIVE.dec();
    }
}

/// Helper used by the accept loop: build a [`SessionHandle`] +
/// matching control receiver, and register the handle. Returns the
/// new session id, the receiver to be moved into the session task,
/// and a clone of the [`SessionInfoHandle`] the session task uses
/// to publish lifecycle metadata for the control socket.
pub fn spawn_handle(
    registry: &Registry,
    peer: SocketAddr,
) -> (
    SessionId,
    mpsc::Receiver<ControlCommand>,
    mpsc::Sender<ControlCommand>,
    SessionInfoHandle,
) {
    let id = SessionId::next();
    let (tx, rx) = mpsc::channel(CONTROL_CHANNEL_DEPTH);
    let info = new_info_handle();
    registry.register(SessionHandle {
        id,
        peer,
        tx: tx.clone(),
        info: info.clone(),
    });
    metrics::CONNECTIONS_ACCEPTED.inc();
    metrics::CONNECTIONS_ACTIVE.inc();
    (id, rx, tx, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_register_and_unregister() {
        let reg = Registry::new();
        let (tx, _rx) = mpsc::channel(1);
        let id = SessionId::next();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        reg.register(SessionHandle {
            id,
            peer,
            tx,
            info: new_info_handle(),
        });
        assert_eq!(reg.len(), 1);
        assert!(reg.get(id).is_some());
        reg.unregister(id);
        assert_eq!(reg.len(), 0);
        assert!(reg.get(id).is_none());
    }

    #[test]
    fn session_ids_are_monotonic() {
        let a = SessionId::next();
        let b = SessionId::next();
        assert!(b.as_u64() > a.as_u64());
    }

    // --- NP filter decision table -----------------------------------

    #[test]
    fn np_filter_passes_control_protocols_unchanged() {
        // LCP / IPCP / PAP / CHAP / EAP all return `NotNetworkLayer`
        // regardless of `network_ready` / `mtu` so the in-process PPP
        // FSM keeps seeing them throughout the session.
        for proto in [0xC021, 0x8021, 0xC023, 0xC223, 0xC227, 0x80FD] {
            assert_eq!(
                np_filter_decide(false, 0, proto, 64),
                NpFilter::NotNetworkLayer,
                "pre-IPCP, proto=0x{proto:04x}",
            );
            assert_eq!(
                np_filter_decide(true, 1500, proto, 64),
                NpFilter::NotNetworkLayer,
                "post-IPCP, proto=0x{proto:04x}",
            );
        }
    }

    #[test]
    fn np_filter_drops_unknown_protocols_as_not_network_layer() {
        // Anything `ProtocolId::from_u16` doesn't recognise falls
        // through to the FSM (which sends a Protocol-Reject under
        // [RFC 1661] §5.7). The NP filter does not invent rejects.
        assert_eq!(
            np_filter_decide(true, 1500, 0xBEEF, 64),
            NpFilter::NotNetworkLayer,
        );
    }

    #[test]
    fn np_filter_drops_ip_pre_ipcp() {
        // IPv4 (0x0021) and IPv6 (0x0057) before NetworkUp.
        assert_eq!(
            np_filter_decide(false, 0, 0x0021, 100),
            NpFilter::DropPreIpcp,
        );
        assert_eq!(
            np_filter_decide(false, 0, 0x0057, 100),
            NpFilter::DropPreIpcp,
        );
    }

    #[test]
    fn np_filter_forwards_ip_at_or_below_mtu() {
        // Boundary condition: payload length == MTU is allowed; >MTU
        // is dropped. MTU here is the body length the netdev was
        // brought up with, not (MTU + headroom).
        assert_eq!(
            np_filter_decide(true, 1400, 0x0021, 1400),
            NpFilter::Forward,
        );
        assert_eq!(
            np_filter_decide(true, 1500, 0x0057, 1500),
            NpFilter::Forward,
        );
    }

    #[test]
    fn np_filter_drops_oversized_ip() {
        assert_eq!(
            np_filter_decide(true, 1400, 0x0021, 1401),
            NpFilter::DropMruExceeded,
        );
        assert_eq!(
            np_filter_decide(true, 1400, 0x0057, 9000),
            NpFilter::DropMruExceeded,
        );
    }

    #[test]
    fn np_filter_drops_pre_ipcp_takes_precedence_over_mru() {
        // If the data path isn't up yet the MTU value is meaningless
        // (and is reported as 0 by the caller). The decision must be
        // `DropPreIpcp`, not `DropMruExceeded`.
        assert_eq!(
            np_filter_decide(false, 0, 0x0021, 9000),
            NpFilter::DropPreIpcp,
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn broadcast_disconnect_delivers_to_all() {
        let reg = Registry::new();
        let mut rxs = Vec::new();
        for i in 0..3 {
            let (tx, rx) = mpsc::channel(1);
            let id = SessionId::next();
            let peer: SocketAddr = format!("127.0.0.1:{}", 1000 + i).parse().unwrap();
            reg.register(SessionHandle {
                id,
                peer,
                tx,
                info: new_info_handle(),
            });
            rxs.push(rx);
        }
        reg.broadcast_disconnect(DisconnectReason::ServerShutdown);
        for mut rx in rxs {
            let cmd = rx.recv().await.expect("disconnect delivered");
            assert!(matches!(
                cmd,
                ControlCommand::Disconnect(DisconnectReason::ServerShutdown)
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn try_send_returns_false_when_session_gone() {
        let reg = Registry::new();
        let (tx, rx) = mpsc::channel(1);
        let id = SessionId::next();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let handle = SessionHandle {
            id,
            peer,
            tx,
            info: new_info_handle(),
        };
        reg.register(handle.clone());
        drop(rx);
        assert!(!handle.try_send(ControlCommand::Disconnect(DisconnectReason::AdminRequested)));
    }
}
