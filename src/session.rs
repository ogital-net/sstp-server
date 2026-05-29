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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::metrics;

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
/// (future) TLS state, SSTP state machine, and PPP control plane are
/// owned here for the session's lifetime; nothing in this task is
/// `Send` once protocol state is in place.
///
/// **v0.1 status.** This is the M6 glue: the task registers itself,
/// selects on `(stream, control_rx, drain_rx)`, unregisters on exit.
/// The actual TLS handshake → SSTP demux → PPP drive loop is a TODO
/// that lands as the surrounding subsystems get wired together end to
/// end. Until then the task drops the connection after the first read
/// readiness event (smoke-test useful, not a real server).
pub async fn run(
    stream: TcpStream,
    peer: SocketAddr,
    id: SessionId,
    registry: Registry,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    mut drain_rx: broadcast::Receiver<()>,
) {
    info!(%id, %peer, "session accepted");

    let _registered = RegistrationGuard {
        registry: &registry,
        id,
    };

    // TODO(M6+): drive TLS handshake (crate::crypto::tls), then run the
    // SSTP state machine (crate::sstp::StateMachine) selecting on the
    // TLS read half, the control channel, and the drain signal. PPP
    // FSM (crate::ppp) runs alongside, RADIUS (crate::auth) is awaited
    // on the auth runtime via a `oneshot`.
    // Single select pass for v0.1 — every arm exits the task. When
    // the full TLS/SSTP/PPP drive loop lands this becomes a real loop
    // again with per-frame work between selects.
    let mut buf = [0u8; 1];
    #[allow(clippy::never_loop)]
    loop {
        tokio::select! {
            biased;
            _ = drain_rx.recv() => {
                info!(%id, "session draining (server shutdown)");
                break;
            }
            cmd = control_rx.recv() => match cmd {
                Some(ControlCommand::Disconnect(reason)) => {
                    info!(%id, ?reason, "session control: disconnect");
                    break;
                }
                None => {
                    debug!(%id, "control channel closed by all senders");
                    break;
                }
            },
            res = stream.peek(&mut buf) => match res {
                Ok(0) => {
                    info!(%id, "peer closed connection");
                    break;
                }
                Ok(_) => {
                    // Placeholder until the TLS / SSTP / PPP drive loop
                    // lands. Drop the connection so peers see a clean
                    // FIN rather than hanging.
                    info!(%id, "received bytes; protocol driver not wired yet");
                    break;
                }
                Err(e) => {
                    warn!(%id, error = %e, "stream peek failed");
                    break;
                }
            },
        }
    }

    info!(%id, "session ended");
    drop(stream);
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
