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
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::auth::bridge::AuthBridge;
use crate::cli::DataPathMode;
use crate::crypto::tls::{SslContext, TlsStream};
use crate::kppp::session::KpppSession;
use crate::metrics;
use crate::ppp::{AuthVerdict, Ppp, PppEvent, PppStep, TimerOwner};
use crate::sstp::preamble;

/// Bounded depth for the per-session control channel. Control commands
/// (Disconnect) are rare enough that any backlog past a couple of slots
/// signals a stuck session — we want to drop rather than queue forever.
const CONTROL_CHANNEL_DEPTH: usize = 4;

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
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Construct from a raw `u64`. Used by the control socket parser
    /// when an operator types `show sess <id>` — there is no
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
    RadiusDisconnect,
    /// Process-wide drain in progress (SIGTERM / `shutdown` command).
    ServerShutdown,
}

/// Cross-worker control commands deliverable to a single session.
#[derive(Debug, Clone)]
pub enum ControlCommand {
    Disconnect(DisconnectReason),
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
}

impl SessionHandle {
    /// Test-only constructor that wires a fresh control channel and
    /// returns both the handle and its receiver. Production code goes
    /// through [`spawn_handle`].
    #[cfg(test)]
    #[must_use]
    pub fn for_test(id: SessionId, peer: SocketAddr) -> (Self, mpsc::Receiver<ControlCommand>) {
        let (tx, rx) = mpsc::channel(CONTROL_CHANNEL_DEPTH);
        (Self { id, peer, tx }, rx)
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
    mut drain_rx: broadcast::Receiver<()>,
    tls_ctx: SslContext,
    auth_bridge: AuthBridge,
    local_ip: Ipv4Addr,
    data_path: DataPathMode,
) {
    info!(%id, %peer, "session accepted");

    let _registered = RegistrationGuard {
        registry: &registry,
        id,
    };

    // Snapshot the server cert hash before consuming the TLS context
    // — we hand it to the SSTP FSM once Call Connect Request lands.
    let cert_hash = tls_ctx.cert_hash_sha256();

    // Phase 1: TLS handshake. Failures here are common in practice
    // (port scanners, readiness probes, TLS-version mismatches) so
    // they are logged at warn — not error — and counted into the
    // single `HANDSHAKE_FAILURES` bucket. Distinguishing TLS vs HTTP
    // vs SSTP-negotiation reasons lands when those layers do
    // (CLAUDE.md M6b onward).
    let mut tls = tokio::select! {
        biased;
        _ = drain_rx.recv() => {
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
            if matches!(e, preamble::PreambleError::Bad(_) | preamble::PreambleError::TooLarge) {
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

    // Phase 3: drive the SSTP state machine until it terminates.
    // PPP wiring (M6d), the RADIUS bridge (M6e) and Crypto Binding
    // verification (M6f) hook in here as those subsystems land —
    // today the loop accepts a `Call-Connect-Request`, responds with
    // an `Ack`, and would normally signal PPP to start LCP. Without
    // a PPP layer the FSM sits in `Server_Call_Connected_Pending`
    // until the negotiation timer fires and the abort sequence
    // drains the connection.
    drive_sstp(id, peer, tls, control_rx, drain_rx, auth_bridge, cert_hash, local_ip, data_path).await;

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
    mut tls: TlsStream,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    mut drain_rx: broadcast::Receiver<()>,
    auth_bridge: AuthBridge,
    cert_hash: [u8; 32],
    local_ip: Ipv4Addr,
    data_path: DataPathMode,
) {
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;
    use tokio::time::Sleep;

    use crate::sstp::frame::SSTP_MAX_PACKET_LEN;
    use crate::sstp::msg::CALL_CONNECTED_LEN;
    use crate::sstp::state::Timer;
    use crate::sstp::{ControlMessage, Packet, StateMachine, parse_control};

    let mut ssm = StateMachine::new(cert_hash);
    let mut tx_buf = [0u8; SSTP_MAX_PACKET_LEN];
    let mut rx_buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    let mut sstp_timer: Option<(Timer, Pin<Box<Sleep>>)> = None;
    let mut ppp: Option<Ppp> = None;
    let mut ppp_timer: Option<(TimerOwner, Pin<Box<Sleep>>)> = None;
    let mut kppp: Option<KpppSession> = None;
    let mut kppp_buf = [0u8; 2048];
    // Mainline `/dev/ppp` unit fds return `Ok(0)` from `read(2)` —
    // the unit fd does not deliver TX frames in userspace (that's a
    // channel-fd path, which requires our SSTP kmod). Until the
    // kmod is wired in, the userspace data path is RX-only; flip
    // this flag after the first spurious EOF and stop polling the
    // unit fd to keep the control plane alive.
    let mut kppp_read_disabled = false;
    let auth = AuthCtx { peer, bridge: &auth_bridge };

    // Spec entry point: `New HTTPS Connection Received` (§3.3.2.1).
    let initial = ssm.on_https_accepted();
    if !handle_sstp_step(
        id, &mut tls, &initial, &tx_buf, &mut sstp_timer, &mut ppp, &mut ppp_timer, &auth,
        local_ip, &mut kppp, data_path,
    )
    .await
    {
        return;
    }

    loop {
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
            // Read one PPP frame from the kernel `pppN` unit fd when
            // present *and* we're on the userspace data path. In
            // kernel mode the SSTP kmod owns the byte path and there
            // is nothing for us to copy.
            let kppp_read_fut = async {
                match kppp.as_ref() {
                    Some(k) if !k.is_kernel() && !kppp_read_disabled => {
                        k.read_frame(&mut kppp_buf).await
                    }
                    _ => std::future::pending::<std::io::Result<usize>>().await,
                }
            };
            tokio::select! {
                biased;
                _ = drain_rx.recv() => DriverEvent::Drain,
                c = control_rx.recv() => DriverEvent::Control(c),
                () = sstp_timer_fut => DriverEvent::SstpTimer,
                () = ppp_timer_fut => DriverEvent::PppTimer,
                r = kppp_read_fut => DriverEvent::KpppRead(r),
                r = tls.read(&mut chunk) => DriverEvent::Read(r),
            }
        };

        match outcome {
            DriverEvent::Drain => {
                info!(%id, "session draining (server shutdown)");
                let out = ssm.on_higher_layer_disconnect(&mut tx_buf);
                if !handle_sstp_step(
                    id,
                    &mut tls,
                    &out,
                    &tx_buf,
                    &mut sstp_timer,
                    &mut ppp,
                    &mut ppp_timer,
                    &auth,
                    local_ip,
                    &mut kppp,
                    data_path,
                )
                .await
                {
                    return;
                }
            }
            DriverEvent::Control(Some(ControlCommand::Disconnect(reason))) => {
                info!(%id, ?reason, "session control: disconnect");
                let out = ssm.on_higher_layer_disconnect(&mut tx_buf);
                if !handle_sstp_step(
                    id,
                    &mut tls,
                    &out,
                    &tx_buf,
                    &mut sstp_timer,
                    &mut ppp,
                    &mut ppp_timer,
                    &auth,
                    local_ip,
                    &mut kppp,
                    data_path,
                )
                .await
                {
                    return;
                }
            }
            DriverEvent::Control(None) => {
                debug!(%id, "control channel closed by all senders");
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
                    &mut tls,
                    &out,
                    &tx_buf,
                    &mut sstp_timer,
                    &mut ppp,
                    &mut ppp_timer,
                    &auth,
                    local_ip,
                    &mut kppp,
                    data_path,
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
                    if !handle_ppp_step(id, &mut tls, p, step, &mut ppp_timer, &auth, local_ip, &mut kppp, data_path).await {
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
                // Mainline ppp_generic returns EOF from a unit-fd
                // read because TX frames flow through channels, not
                // the unit. TUN by contrast returns EOF only on
                // genuine close. Branch on backend.
                if kppp.as_ref().is_some_and(KpppSession::is_tun) {
                    warn!(%id, "tun fd returned EOF; tearing down session");
                    return;
                }
                warn!(%id, "ppp unit fd returned EOF; userspace RX path disabled (no kernel channel; needs sstp kmod + kTLS)");
                kppp_read_disabled = true;
            }
            DriverEvent::KpppRead(Ok(n)) => {
                if let Err(e) = write_ppp_as_sstp_data(&mut tls, &kppp_buf[..n]).await {
                    warn!(%id, error = %e, "TLS write of kernel-PPP frame failed");
                    return;
                }
                if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut tls).await {
                    warn!(%id, error = %e, "TLS flush after kernel-PPP frame failed");
                    return;
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
                rx_buf.extend_from_slice(&chunk[..n]);
                // Drain as many complete SSTP packets as the buffer
                // currently holds. The codec is zero-copy against the
                // borrowed slice; we copy out the consumed bytes via
                // `drain` at the end of each iteration.
                loop {
                    let parsed = Packet::parse(&rx_buf);
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
                                &mut tls,
                                &out,
                                &tx_buf,
                                &mut sstp_timer,
                                &mut ppp,
                                &mut ppp_timer,
                                &auth,
                                local_ip,
                                &mut kppp,
                                data_path,
                            )
                            .await
                            {
                                return;
                            }
                            let mut routed_to_kernel = false;
                            if let Some(k) = kppp.as_ref()
                                && !k.is_kernel()
                                && let Ok(frame) = crate::ppp::frame::decode_frame(payload)
                                && frame.protocol
                                    == crate::ppp::frame::ProtocolId::Ip.as_u16()
                            {
                                if let Err(e) = k.write_frame(payload).await {
                                    warn!(%id, error = %e, "kernel PPP unit write failed");
                                }
                                routed_to_kernel = true;
                            }
                            if !routed_to_kernel
                                && let Some(p) = ppp.as_mut()
                            {
                                let step = p.on_frame(payload);
                                if !handle_ppp_step(id, &mut tls, p, step, &mut ppp_timer, &auth, local_ip, &mut kppp, data_path).await {
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
                                            zeroed.copy_from_slice(&rx_buf[..CALL_CONNECTED_LEN]);
                                            zeroed[80..112].fill(0);
                                            ssm.verify_call_connected(cb, &zeroed, &mut tx_buf)
                                        }
                                        other => ssm.on_message(other, &mut tx_buf),
                                    };
                                    if !handle_sstp_step(
                                        id,
                                        &mut tls,
                                        &out,
                                        &tx_buf,
                                        &mut sstp_timer,
                                        &mut ppp,
                                        &mut ppp_timer,
                                        &auth,
                                        local_ip,
                                        &mut kppp,
                                        data_path,
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
                    rx_buf.drain(..consumed);
                }
            }
        }
    }
}

/// One-shot description of which select arm fired. Kept local to
/// [`drive_sstp`] because it has no other consumers.
enum DriverEvent {
    Drain,
    Control(Option<ControlCommand>),
    SstpTimer,
    PppTimer,
    KpppRead(std::io::Result<usize>),
    Read(std::io::Result<usize>),
}

/// Apply an SSTP [`StepOut`] via [`apply_step`], then handle any
/// `NotifyHigher` that resulted by spinning up the PPP driver
/// (`StartPpp`) or logging (`SstpEstablished`). Returns `false` when
/// the driver should exit.
#[allow(clippy::too_many_arguments)]
async fn handle_sstp_step(
    id: SessionId,
    tls: &mut TlsStream,
    out: &crate::sstp::StepOut,
    tx_buf: &[u8],
    sstp_timer: &mut Option<(
        crate::sstp::state::Timer,
        std::pin::Pin<Box<tokio::time::Sleep>>,
    )>,
    ppp: &mut Option<Ppp>,
    ppp_timer: &mut Option<(TimerOwner, std::pin::Pin<Box<tokio::time::Sleep>>)>,
    auth: &AuthCtx<'_>,
    local_ip: Ipv4Addr,
    kppp: &mut Option<KpppSession>,
    data_path: DataPathMode,
) -> bool {
    let outcome = apply_step(id, tls, out, tx_buf, sstp_timer).await;
    if !outcome.keep_going {
        return false;
    }
    if outcome.start_ppp {
        if ppp.is_some() {
            debug!(%id, "spurious StartPpp notify after PPP already running");
            return true;
        }
        info!(%id, "starting PPP control plane");
        let mut new_ppp = Ppp::new();
        let step = new_ppp.open();
        *ppp = Some(new_ppp);
        if !handle_ppp_step(
            id,
            tls,
            ppp.as_mut().expect("just inserted"),
            step,
            ppp_timer,
            auth,
            local_ip,
            kppp,
            data_path,
        )
        .await
        {
            return false;
        }
    }
    true
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
    tls: &mut TlsStream,
    ppp: &mut Ppp,
    mut step: PppStep,
    ppp_timer: &mut Option<(TimerOwner, std::pin::Pin<Box<tokio::time::Sleep>>)>,
    auth: &AuthCtx<'_>,
    local_ip: Ipv4Addr,
    kppp: &mut Option<KpppSession>,
    data_path: DataPathMode,
) -> bool {
    use tokio::time::{Instant, sleep_until};

    // Loop because handling an event (e.g. PAP auth result) re-enters
    // the driver and may produce more frames and another event.
    loop {
        for frame in &step.frames {
            if let Err(e) = write_ppp_as_sstp_data(tls, frame).await {
                warn!(%id, error = %e, "TLS write of PPP frame failed");
                return false;
            }
        }
        if !step.frames.is_empty() {
            if let Err(e) = tokio::io::AsyncWriteExt::flush(tls).await {
                warn!(%id, error = %e, "TLS flush failed");
                return false;
            }
        }
        for owner in &step.timer_stops {
            if ppp_timer.as_ref().is_some_and(|(o, _)| o == owner) {
                *ppp_timer = None;
            }
        }
        for (owner, dur) in &step.timer_starts {
            let sleep = Box::pin(sleep_until(Instant::now() + *dur));
            *ppp_timer = Some((*owner, sleep));
        }

        let event = step.event.take();
        let finished = step.finished;

        match event {
            Some(PppEvent::NeedPapAuth { peer_id, password }) => {
                let user = String::from_utf8_lossy(&peer_id).into_owned();
                info!(%id, user = %user, "PAP credentials received; dispatching to RADIUS");
                let verdict = auth
                    .bridge
                    .submit_pap(user.clone(), password, auth.peer, None)
                    .await;
                match &verdict {
                    AuthVerdict::Accept { addrs } => {
                        info!(%id, user = %user, ip = ?addrs.ip, "RADIUS Access-Accept");
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
            Some(PppEvent::NetworkUp(addrs)) => {
                let peer_ip = Ipv4Addr::from(addrs.ip);
                if kppp.is_some() {
                    debug!(%id, ip = %peer_ip, "spurious NetworkUp after kernel PPP unit already attached");
                } else {
                    let ktls = tls.ktls_eligibility();
                    let effective_data_path = match data_path {
                        DataPathMode::Auto if !ktls.compatible => {
                            info!(
                                %id,
                                tls_version = %ktls.tls_version,
                                cipher = %ktls.cipher,
                                "kTLS-incompatible TLS session; using /dev/ppp userspace data path"
                            );
                            DataPathMode::Userspace
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

                    match KpppSession::bring_up(effective_data_path, tls.tcp_fd(), local_ip, peer_ip) {
                        Ok(k) => {
                            info!(
                                %id,
                                ifname = %k.ifname(),
                                ifindex = k.ifindex(),
                                local = %local_ip,
                                peer = %peer_ip,
                                tls_version = %ktls.tls_version,
                                cipher = %ktls.cipher,
                                kernel_path = k.is_kernel(),
                                "kernel PPP unit attached"
                            );
                            *kppp = Some(k);
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
}

/// Wrap a raw PPP frame in an SSTP data packet and write it to TLS.
async fn write_ppp_as_sstp_data(tls: &mut TlsStream, payload: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    use crate::sstp::frame::{SSTP_HEADER_LEN, SSTP_MAX_PACKET_LEN, write_header};

    let total = SSTP_HEADER_LEN + payload.len();
    debug_assert!(
        total <= SSTP_MAX_PACKET_LEN,
        "PPP frame exceeds SSTP MTU: {total}"
    );
    let mut header = [0u8; SSTP_HEADER_LEN];
    write_header(&mut header, false, total);
    tls.write_all(&header).await?;
    tls.write_all(payload).await?;
    Ok(())
}

/// Apply a [`StepOut`] from the SSTP state machine: write any
/// outbound bytes, update the SSTP timer slot, and decode the
/// terminate flag plus higher-layer notification. Returns
/// [`SstpOutcome`] for the caller to act on (PPP wire-up happens in
/// [`handle_sstp_step`]).
async fn apply_step(
    id: SessionId,
    tls: &mut TlsStream,
    out: &crate::sstp::StepOut,
    tx_buf: &[u8],
    active_timer: &mut Option<(
        crate::sstp::state::Timer,
        std::pin::Pin<Box<tokio::time::Sleep>>,
    )>,
) -> SstpOutcome {
    use tokio::io::AsyncWriteExt;
    use tokio::time::{Instant, sleep_until};

    use crate::sstp::state::{NotifyHigher, Terminate};

    if out.send_len > 0 {
        if let Err(e) = tls.write_all(&tx_buf[..out.send_len]).await {
            warn!(%id, error = %e, "TLS write failed");
            return SstpOutcome::stop();
        }
        if let Err(e) = tls.flush().await {
            warn!(%id, error = %e, "TLS flush failed");
            return SstpOutcome::stop();
        }
    }

    if let Some(stop) = out.timer_stop
        && active_timer
            .as_ref()
            .is_some_and(|(t, _)| *t == stop)
    {
        *active_timer = None;
    }
    if let Some((which, dur)) = out.timer_start {
        let sleep = Box::pin(sleep_until(Instant::now() + dur));
        *active_timer = Some((which, sleep));
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
/// matching control receiver, and register the handle.
pub fn spawn_handle(registry: &Registry, peer: SocketAddr) -> (SessionId, mpsc::Receiver<ControlCommand>) {
    let id = SessionId::next();
    let (tx, rx) = mpsc::channel(CONTROL_CHANNEL_DEPTH);
    registry.register(SessionHandle { id, peer, tx });
    metrics::CONNECTIONS_ACCEPTED.inc();
    metrics::CONNECTIONS_ACTIVE.inc();
    (id, rx)
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
        reg.register(SessionHandle { id, peer, tx });
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

    #[tokio::test(flavor = "current_thread")]
    async fn broadcast_disconnect_delivers_to_all() {
        let reg = Registry::new();
        let mut rxs = Vec::new();
        for i in 0..3 {
            let (tx, rx) = mpsc::channel(1);
            let id = SessionId::next();
            let peer: SocketAddr = format!("127.0.0.1:{}", 1000 + i).parse().unwrap();
            reg.register(SessionHandle { id, peer, tx });
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
        let handle = SessionHandle { id, peer, tx };
        reg.register(handle.clone());
        drop(rx);
        assert!(!handle.try_send(ControlCommand::Disconnect(DisconnectReason::AdminRequested)));
    }
}
