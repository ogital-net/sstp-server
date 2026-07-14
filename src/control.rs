//! JSON-RPC 2.0 control socket (M7).
//!
//! Runs on the auth runtime, never on an I/O worker, so a slow consumer
//! cannot stall the packet path. NUL-delimited JSON-RPC 2.0 over a
//! Unix-domain stream socket, served by [`jasonrpc`].
//!
//! Access control is the filesystem: the socket file is created `0660`,
//! group-owned by whatever group the process runs as. No in-band
//! authentication.
//!
//! ## Methods
//!
//! | Method               | Params          | Description                              |
//! |----------------------|-----------------|------------------------------------------|
//! | `show.info`          | —               | Version, uptime, thread counts, sessions |
//! | `show.stat`          | —               | Metrics snapshot (key → value map)       |
//! | `show.session.list`  | —               | List active sessions                     |
//! | `show.session.get`   | `{id: u64}`     | Details for a single session             |
//! | `session.disable`    | `{id: u64}`     | Tear down a session by id                |
//! | `session.rekey`      | `{id: u64, ...}`| Force TLS 1.3 KeyUpdate on a session     |
//! | `shutdown`           | —               | Ask the daemon to drain and exit         |

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use jasonrpc::server::Router;
use jasonrpc::transport::Delimited;
use jasonrpc::transport::io::FramedConn;
use jasonrpc::{Error as RpcError, Request};
use serde::Serialize;
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::cli;
use crate::metrics;
use crate::session::{ControlCommand, DisconnectReason, Registry, SessionId};

const SOCKET_MODE: u32 = 0o660;

#[derive(Debug, Error)]
pub enum BindError {
    #[error("removing stale socket {path}: {source}")]
    Remove {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("binding control socket {path}: {source}")]
    Bind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("setting permissions on {path}: {source}")]
    Permissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// State the dispatcher needs to render responses and act on the
/// process. Wrapped in `Arc` for sharing across handler tasks via
/// `jasonrpc::server::Router::with_state`.
#[derive(Clone)]
pub struct ControlState {
    pub registry: Registry,
    pub shutdown_tx: watch::Sender<bool>,
    pub started: Instant,
    pub io_threads: usize,
    pub auth_threads: usize,
}

/// Bind the control socket file synchronously and return both the
/// `std::os::unix::net::UnixListener` (so the caller can register it
/// with a tokio runtime after `privdrop`) and the path to the socket
/// file (re-emitted so callers don't have to track it separately).
///
/// Removes a stale socket file from a previous run, sets `0660`
/// permissions, and `chown`s the socket to `(uid, gid)` when the
/// owner is provided — useful when the daemon will `setuid` away
/// from root after this call.
pub fn bind(
    path: &Path,
    owner: Option<(libc::uid_t, libc::gid_t)>,
) -> Result<std::os::unix::net::UnixListener, BindError> {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(BindError::Remove {
            path: path.to_path_buf(),
            source: e,
        });
    }

    let listener =
        std::os::unix::net::UnixListener::bind(path).map_err(|source| BindError::Bind {
            path: path.to_path_buf(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| BindError::Bind {
            path: path.to_path_buf(),
            source,
        })?;
    let perms = std::fs::Permissions::from_mode(SOCKET_MODE);
    std::fs::set_permissions(path, perms).map_err(|source| BindError::Permissions {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some((uid, gid)) = owner {
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|source| {
                BindError::Permissions {
                    path: path.to_path_buf(),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
                }
            })?;
        // SAFETY: `chown` takes a NUL-terminated path and uid/gid
        // values; we own `c_path` for the duration of the call.
        let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
        if rc != 0 {
            return Err(BindError::Permissions {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
    }
    Ok(listener)
}

/// Build the JSON-RPC [`Router`] with all registered methods.
fn build_router(state: Arc<ControlState>) -> Router<Arc<ControlState>> {
    Router::with_state(state)
        .register(
            "show.info",
            |state: Arc<ControlState>, _req: Request| async move { Ok(render_info(&state)) },
        )
        .register(
            "show.stat",
            |_state: Arc<ControlState>, _req: Request| async move { Ok(render_stats_map()) },
        )
        .register(
            "show.session.list",
            |state: Arc<ControlState>, _req: Request| async move { Ok(render_sess_list(&state)) },
        )
        .register(
            "show.session.get",
            |state: Arc<ControlState>, req: Request| async move {
                #[derive(serde::Deserialize)]
                struct Params {
                    id: u64,
                }
                let p: Params = req.params_as().ok_or_else(RpcError::invalid_params)?;
                Ok(render_sess_one(&state, p.id))
            },
        )
        .register(
            "session.disable",
            |state: Arc<ControlState>, req: Request| async move {
                #[derive(serde::Deserialize)]
                struct Params {
                    id: u64,
                }
                let p: Params = req.params_as().ok_or_else(RpcError::invalid_params)?;
                Ok(disable_session(&state, p.id))
            },
        )
        .register(
            "session.rekey",
            |state: Arc<ControlState>, req: Request| async move {
                #[derive(serde::Deserialize)]
                struct Params {
                    id: u64,
                    #[serde(default)]
                    request_peer: bool,
                }
                let p: Params = req.params_as().ok_or_else(RpcError::invalid_params)?;
                Ok(rekey_session(&state, p.id, p.request_peer))
            },
        )
        .register(
            "shutdown",
            |state: Arc<ControlState>, _req: Request| async move { Ok(shutdown(&state)) },
        )
}

/// Run the accept loop over a pre-bound listener until `shutdown_rx`
/// fires. `path` is only used so the socket file can be unlinked on
/// shutdown — the caller is responsible for having already opened
/// the socket via [`bind`].
pub async fn serve(
    path: PathBuf,
    listener: std::os::unix::net::UnixListener,
    state: ControlState,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), BindError> {
    let listener = UnixListener::from_std(listener).map_err(|source| BindError::Bind {
        path: path.clone(),
        source,
    })?;
    let router = build_router(Arc::new(state));
    info!(
        path = %path.display(),
        mode = format!("{:o}", SOCKET_MODE),
        "control socket ready"
    );

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                debug!("control socket draining");
                break;
            }
            res = listener.accept() => match res {
                Ok((stream, _addr)) => {
                    let router = router.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &router).await {
                            debug!(error = %e, "control connection ended");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "control socket accept failed"),
            }
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Handle a single control-socket connection. Reads NUL-delimited
/// frames, dispatches them through the [`Router`], and writes the
/// responses back.
async fn handle_connection<S>(
    stream: UnixStream,
    router: &Router<S>,
) -> Result<(), jasonrpc::error::TransportError>
where
    S: Clone + Send + Sync + 'static,
{
    let mut conn = FramedConn::new(stream, Delimited::new(b'\0'));
    loop {
        let Some(frame) = conn.recv().await? else {
            return Ok(()); // clean EOF
        };
        let output = router.handle_bytes(&frame).await;
        match output.to_bytes() {
            Ok(Some(response_bytes)) => {
                conn.send(&response_bytes).await?;
            }
            Ok(None) => {} // notification — no response per JSON-RPC 2.0
            Err(e) => {
                warn!(error = %e, "router to_bytes failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Response types — all Serialize so the Router can emit them as JSON.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct InfoResponse {
    version: String,
    uptime_seconds: u64,
    io_threads: usize,
    auth_threads: usize,
    active_sessions: usize,
}

#[derive(Serialize)]
struct SessionListItem {
    id: String,
    peer: String,
    user: String,
    ip: String,
    uptime: String,
    backend: String,
    cipher: String,
}

#[derive(Serialize)]
struct SessionDetail {
    id: String,
    peer: String,
    uptime: String,
    user: String,
    auth_method: String,
    assigned_ip: String,
    local_ip: String,
    ifname: String,
    backend: String,
    mtu: String,
    tls_version: String,
    cipher: String,
    correlation_id: String,
    rate_egress: String,
    rate_ingress: String,
}

#[derive(Serialize)]
struct SessionDisableResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
struct SessionRekeyResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
struct ShutdownResult {
    message: String,
}

// ---------------------------------------------------------------------------
// Handler implementations — pure functions from ControlState, testable
// without the Router or any I/O.
// ---------------------------------------------------------------------------

fn render_info(state: &ControlState) -> InfoResponse {
    InfoResponse {
        version: cli::version_string(),
        uptime_seconds: state.started.elapsed().as_secs(),
        io_threads: state.io_threads,
        auth_threads: state.auth_threads,
        active_sessions: state.registry.len(),
    }
}

fn render_stats_map() -> serde_json::Value {
    serde_json::json!({
        "sstp_connections_accepted": metrics::CONNECTIONS_ACCEPTED.get(),
        "sstp_connections_active": metrics::CONNECTIONS_ACTIVE.get(),
        "sstp_handshake_failures": metrics::HANDSHAKE_FAILURES.get(),
        "sstp_auth_accept": metrics::AUTH_ACCEPT.get(),
        "sstp_auth_reject": metrics::AUTH_REJECT.get(),
        "sstp_session_teardown_clean": metrics::SESSION_TEARDOWN_CLEAN.get(),
        "sstp_session_teardown_admin": metrics::SESSION_TEARDOWN_ADMIN.get(),
        "sstp_session_teardown_coa": metrics::SESSION_TEARDOWN_COA.get(),
        "sstp_session_teardown_shutdown": metrics::SESSION_TEARDOWN_SHUTDOWN.get(),
        "sstp_session_teardown_rekey_handshake": metrics::SESSION_TEARDOWN_REKEY_HANDSHAKE.get(),
        "sstp_session_teardown_rekey_alert": metrics::SESSION_TEARDOWN_REKEY_ALERT.get(),
        "sstp_session_teardown_rekey_other": metrics::SESSION_TEARDOWN_REKEY_OTHER.get(),
        "sstp_session_panics": metrics::SESSION_PANICS.get(),
        "sstp_crypto_binding_failures": metrics::CRYPTO_BINDING_FAILURES.get(),
        "sstp_np_filter_drops_pre_ipcp": metrics::NP_FILTER_DROPS_PRE_IPCP.get(),
        "sstp_np_filter_drops_mru": metrics::NP_FILTER_DROPS_MRU.get(),
        "sstp_log_lines_dropped": metrics::LOG_LINES_DROPPED.get(),
    })
}

fn render_sess_list(state: &ControlState) -> Vec<SessionListItem> {
    state
        .registry
        .snapshot()
        .into_iter()
        .map(|h| {
            let i = h.info();
            SessionListItem {
                id: h.id.to_string(),
                peer: h.peer.to_string(),
                user: i.username.unwrap_or_else(|| "-".to_string()),
                ip: i
                    .assigned_ip
                    .map_or_else(|| "-".to_string(), |a| a.to_string()),
                uptime: i
                    .started_at
                    .map_or_else(|| "-".to_string(), |t| format_duration(t.elapsed())),
                backend: i.backend.unwrap_or("-").to_string(),
                cipher: i.cipher.unwrap_or_else(|| "-".to_string()),
            }
        })
        .collect()
}

fn render_sess_one(state: &ControlState, raw_id: u64) -> SessionDetail {
    let id = SessionId::from_u64(raw_id);
    let h = state.registry.get(id);
    SessionDetail {
        id: raw_id.to_string(),
        peer: h.as_ref().map_or("-".to_string(), |h| h.peer.to_string()),
        uptime: h.as_ref().map_or("-".to_string(), |h| {
            let i = h.info();
            i.started_at
                .map_or_else(|| "-".to_string(), |t| format_duration(t.elapsed()))
        }),
        user: h
            .as_ref()
            .and_then(|h| h.info().username)
            .unwrap_or_else(|| "-".to_string()),
        auth_method: h
            .as_ref()
            .and_then(|h| h.info().auth_method)
            .map_or_else(|| "-".to_string(), |m| format!("{m:?}")),
        assigned_ip: h
            .as_ref()
            .and_then(|h| h.info().assigned_ip)
            .map_or_else(|| "-".to_string(), |a| a.to_string()),
        local_ip: h
            .as_ref()
            .and_then(|h| h.info().local_ip)
            .map_or_else(|| "-".to_string(), |a| a.to_string()),
        ifname: h
            .as_ref()
            .and_then(|h| h.info().ifname)
            .unwrap_or_else(|| "-".to_string()),
        backend: h
            .as_ref()
            .and_then(|h| h.info().backend)
            .unwrap_or("-")
            .to_string(),
        mtu: h
            .as_ref()
            .and_then(|h| h.info().mtu)
            .map_or_else(|| "-".to_string(), |m| m.to_string()),
        tls_version: h
            .as_ref()
            .and_then(|h| h.info().tls_version)
            .unwrap_or_else(|| "-".to_string()),
        cipher: h
            .as_ref()
            .and_then(|h| h.info().cipher)
            .unwrap_or_else(|| "-".to_string()),
        correlation_id: h
            .as_ref()
            .and_then(|h| h.info().correlation_id)
            .unwrap_or_else(|| "-".to_string()),
        rate_egress: h.as_ref().map_or("-".to_string(), |h| {
            let info = h.info();
            format_rate(info.shaping.as_ref().and_then(|s| s.egress.as_ref()))
        }),
        rate_ingress: h.as_ref().map_or("-".to_string(), |h| {
            let info = h.info();
            format_rate(info.shaping.as_ref().and_then(|s| s.ingress.as_ref()))
        }),
    }
}

fn disable_session(state: &ControlState, raw_id: u64) -> SessionDisableResult {
    let id = SessionId::from_u64(raw_id);
    let Some(h) = state.registry.get(id) else {
        return SessionDisableResult {
            ok: false,
            message: format!("no such session {raw_id}"),
        };
    };
    if h.try_send(ControlCommand::Disconnect(DisconnectReason::AdminRequested)) {
        SessionDisableResult {
            ok: true,
            message: format!("disconnect queued for session {raw_id}"),
        }
    } else {
        SessionDisableResult {
            ok: false,
            message: format!("session {raw_id} could not be notified (queue full or exiting)"),
        }
    }
}

fn rekey_session(state: &ControlState, raw_id: u64, request_peer: bool) -> SessionRekeyResult {
    let id = SessionId::from_u64(raw_id);
    let Some(h) = state.registry.get(id) else {
        return SessionRekeyResult {
            ok: false,
            message: format!("no such session {raw_id}"),
        };
    };
    if h.try_send(ControlCommand::Rekey { request_peer }) {
        let label = if request_peer {
            "rekey queued (with update_requested)"
        } else {
            "rekey queued"
        };
        SessionRekeyResult {
            ok: true,
            message: format!("{label} for session {raw_id}"),
        }
    } else {
        SessionRekeyResult {
            ok: false,
            message: format!("session {raw_id} could not be notified (queue full or exiting)"),
        }
    }
}

fn shutdown(state: &ControlState) -> ShutdownResult {
    let _ = state.shutdown_tx.send(true);
    ShutdownResult {
        message: "shutting down".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_duration(d: std::time::Duration) -> String {
    let total = d.as_secs();
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

fn format_rate(rate: Option<&crate::shape::RateSpec>) -> String {
    match rate {
        None => "-".to_string(),
        Some(r) => match r.burst_rate_bps {
            Some(b) => format!("{}/burst {}", r.rate_bps, b),
            None => format!("{}", r.rate_bps),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> (ControlState, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        let state = ControlState {
            registry: Registry::new(),
            shutdown_tx: tx,
            started: Instant::now(),
            io_threads: 2,
            auth_threads: 1,
        };
        (state, rx)
    }

    #[test]
    fn show_info_includes_uptime_and_threads() {
        let (state, _rx) = test_state();
        let out = render_info(&state);
        // version_string is either "0.1.0" or "0.1.0 (sha date)" — never
        // contains the crate name (that's the CLI --version format).
        assert!(!out.version.is_empty());
        assert_eq!(out.io_threads, 2);
        assert_eq!(out.auth_threads, 1);
        assert_eq!(out.active_sessions, 0);
    }

    #[test]
    fn show_stat_has_expected_keys() {
        let (_state, _rx) = test_state();
        let map = render_stats_map();
        let obj = map.as_object().unwrap();
        assert!(obj.contains_key("sstp_connections_accepted"));
        assert!(obj.contains_key("sstp_connections_active"));
    }

    #[test]
    fn show_session_list_empty_then_one() {
        let (state, _rx) = test_state();
        assert!(render_sess_list(&state).is_empty());

        let id = SessionId::next();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, _session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);

        let list = render_sess_list(&state);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id.to_string());
        assert!(list[0].peer.contains("127.0.0.1:5555"));
    }

    #[test]
    fn session_detail_unknown_id_returns_hyphens() {
        let (state, _rx) = test_state();
        let d = render_sess_one(&state, 999_999);
        assert_eq!(d.peer, "-");
        assert_eq!(d.user, "-");
    }

    #[test]
    fn disable_unknown_session_returns_error() {
        let (state, _rx) = test_state();
        let r = disable_session(&state, 999_999);
        assert!(!r.ok);
        assert!(r.message.contains("no such session"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disable_known_session_queues_disconnect() {
        let (state, _rx) = test_state();
        let id = SessionId::next();
        let raw = id.as_u64();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, mut session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        let r = disable_session(&state, raw);
        assert!(r.ok);
        let cmd = session_rx.recv().await.expect("disconnect delivered");
        assert!(matches!(
            cmd,
            ControlCommand::Disconnect(DisconnectReason::AdminRequested)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rekey_session_default_does_not_request_peer() {
        let (state, _rx) = test_state();
        let id = SessionId::next();
        let raw = id.as_u64();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, mut session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        let r = rekey_session(&state, raw, false);
        assert!(r.ok);
        assert!(!r.message.contains("update_requested"));
        let cmd = session_rx.recv().await.expect("rekey delivered");
        assert!(matches!(
            cmd,
            ControlCommand::Rekey {
                request_peer: false
            }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rekey_session_request_sets_peer_flag() {
        let (state, _rx) = test_state();
        let id = SessionId::next();
        let raw = id.as_u64();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, mut session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        let r = rekey_session(&state, raw, true);
        assert!(r.ok);
        assert!(r.message.contains("update_requested"));
        let cmd = session_rx.recv().await.expect("rekey delivered");
        assert!(matches!(cmd, ControlCommand::Rekey { request_peer: true }));
    }

    #[test]
    fn shutdown_sends_on_channel() {
        let (state, mut rx) = test_state();
        let r = shutdown(&state);
        assert_eq!(r.message, "shutting down");
        assert!(rx.has_changed().unwrap());
        assert!(*rx.borrow_and_update());
    }
}
