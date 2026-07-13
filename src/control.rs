//! HAProxy-style Unix-domain admin socket (M7).
//!
//! Runs on the auth runtime, never on an I/O worker, so a slow `socat`
//! consumer cannot stall the packet path. Line-oriented text protocol:
//! one request line, one response (terminated by an empty line on
//! success or `Error: <msg>\n` on failure), then the client can issue
//! another command on the same connection.
//!
//! Access control is the filesystem: the socket file is created
//! `0660`, group-owned by whatever group the process runs as. No
//! in-band authentication.
//!
//! Command grammar (whitespace-separated tokens, case-sensitive to
//! match `HAProxy` convention):
//!
//! ```text
//! show info
//! show stat
//! show session
//! show session <id>
//! disable session <id>
//! shutdown
//! help
//! ```
//!
//! Unknown commands return `Error: unknown command\n` and the
//! connection stays open.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::cli;
use crate::metrics;
use crate::session::{ControlCommand, DisconnectReason, Registry, SessionId};

const SOCKET_MODE: u32 = 0o660;
const COMMAND_LINE_LIMIT: usize = 1024;

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
/// process. Cloneable; the same view is handed to every connection
/// task.
#[derive(Clone)]
pub struct ControlState {
    pub registry: Registry,
    pub shutdown_tx: broadcast::Sender<()>,
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

/// Run the accept loop over a pre-bound listener until `shutdown_rx`
/// fires. `path` is only used so the socket file can be unlinked on
/// shutdown — the caller is responsible for having already opened
/// the socket via [`bind`].
pub async fn serve(
    path: PathBuf,
    listener: std::os::unix::net::UnixListener,
    state: ControlState,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<(), BindError> {
    let listener = UnixListener::from_std(listener).map_err(|source| BindError::Bind {
        path: path.clone(),
        source,
    })?;
    info!(path = %path.display(), mode = format!("{:o}", SOCKET_MODE), "control socket ready");

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.recv() => {
                debug!("control socket draining");
                break;
            }
            res = listener.accept() => match res {
                Ok((stream, _addr)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state).await {
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

async fn handle_connection(stream: UnixStream, state: ControlState) -> std::io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        if line.len() > COMMAND_LINE_LIMIT {
            wr.write_all(b"Error: command too long\n\n").await?;
            continue;
        }
        let response = dispatch(line.trim(), &state);
        wr.write_all(response.as_bytes()).await?;
        if !response.ends_with('\n') {
            wr.write_all(b"\n").await?;
        }
        // Blank-line terminator so clients can frame the response.
        wr.write_all(b"\n").await?;
        if response_requested_close(&response) {
            return Ok(());
        }
    }
}

/// `shutdown` causes the dispatcher to drop the connection after the
/// acknowledgement so the operator's `socat - UNIX-CONNECT:...` exits
/// cleanly rather than blocking on the next read.
fn response_requested_close(resp: &str) -> bool {
    resp.starts_with("Shutting down")
}

/// Pure command dispatcher. Split from the I/O layer so it is unit
/// testable without spinning up a Unix socket.
pub fn dispatch(line: &str, state: &ControlState) -> String {
    let toks: Vec<&str> = line.split_ascii_whitespace().collect();
    match toks.as_slice() {
        [] => String::new(),
        ["help"] => help_text().to_string(),
        ["show", "info"] => render_info(state),
        ["show", "stat"] => metrics::render_stats(),
        ["show", "session"] => render_sess_list(state),
        ["show", "session", id] => render_sess_one(state, id),
        ["disable", "session", id] => disable_session(state, id),
        ["rekey", "session"] => "Error: usage: rekey session <id> [request]".to_string(),
        ["rekey", "session", id] => rekey_session(state, id, false),
        ["rekey", "session", id, "request"] => rekey_session(state, id, true),
        ["shutdown"] => shutdown(state),
        _ => "Error: unknown command (try 'help')".to_string(),
    }
}

fn help_text() -> &'static str {
    "Commands:\n\
     show info\n\
     show stat\n\
     show session\n\
     show session <id>\n\
     disable session <id>\n\
     rekey session <id> [request]\n\
     shutdown\n\
     help"
}

fn render_info(state: &ControlState) -> String {
    let uptime = state.started.elapsed();
    format!(
        "version: {version}\n\
         uptime_seconds: {uptime}\n\
         io_threads: {io}\n\
         auth_threads: {auth}\n\
         active_sessions: {sessions}",
        version = cli::version_string(),
        uptime = uptime.as_secs(),
        io = state.io_threads,
        auth = state.auth_threads,
        sessions = state.registry.len(),
    )
}

fn render_sess_list(state: &ControlState) -> String {
    use std::fmt::Write as _;
    let snapshot = state.registry.snapshot();
    if snapshot.is_empty() {
        return "(no active sessions)".to_string();
    }
    let mut out = String::with_capacity(snapshot.len() * 96);
    let _ = writeln!(out, "id\tpeer\tuser\tip\tuptime\tbackend\tcipher");
    for h in snapshot {
        let i = h.info();
        let user = i.username.as_deref().unwrap_or("-");
        let ip = i
            .assigned_ip
            .map_or_else(|| "-".to_string(), |a| a.to_string());
        let uptime = i
            .started_at
            .map_or_else(|| "-".to_string(), |t| format_duration(t.elapsed()));
        let backend = i.backend.unwrap_or("-");
        let cipher = i.cipher.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            h.id, h.peer, user, ip, uptime, backend, cipher
        );
    }
    out.pop();
    out
}

fn render_sess_one(state: &ControlState, id_str: &str) -> String {
    use std::fmt::Write as _;
    let Some(id) = parse_session_id(id_str) else {
        return format!("Error: invalid session id {id_str:?}");
    };
    let Some(h) = state.registry.get(id) else {
        return format!("Error: no such session {id}");
    };
    let i = h.info();
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "id: {}", h.id);
    let _ = writeln!(out, "peer: {}", h.peer);
    let _ = writeln!(
        out,
        "uptime: {}",
        i.started_at
            .map_or_else(|| "-".to_string(), |t| format_duration(t.elapsed()))
    );
    let _ = writeln!(out, "user: {}", i.username.as_deref().unwrap_or("-"));
    let _ = writeln!(
        out,
        "auth_method: {}",
        i.auth_method
            .map_or_else(|| "-".to_string(), |m| format!("{m:?}"))
    );
    let _ = writeln!(
        out,
        "assigned_ip: {}",
        i.assigned_ip
            .map_or_else(|| "-".to_string(), |a| a.to_string())
    );
    let _ = writeln!(
        out,
        "local_ip: {}",
        i.local_ip
            .map_or_else(|| "-".to_string(), |a| a.to_string())
    );
    let _ = writeln!(out, "ifname: {}", i.ifname.as_deref().unwrap_or("-"));
    let _ = writeln!(out, "backend: {}", i.backend.unwrap_or("-"));
    let _ = writeln!(
        out,
        "mtu: {}",
        i.mtu.map_or_else(|| "-".to_string(), |m| m.to_string())
    );
    let _ = writeln!(
        out,
        "tls_version: {}",
        i.tls_version.as_deref().unwrap_or("-")
    );
    let _ = writeln!(out, "cipher: {}", i.cipher.as_deref().unwrap_or("-"));
    let _ = writeln!(
        out,
        "correlation_id: {}",
        i.correlation_id.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        out,
        "rate_egress: {}",
        format_rate(i.shaping.as_ref().and_then(|s| s.egress.as_ref()))
    );
    let _ = writeln!(
        out,
        "rate_ingress: {}",
        format_rate(i.shaping.as_ref().and_then(|s| s.ingress.as_ref()))
    );
    out.pop();
    out
}

/// Format a `std::time::Duration` as `HHh MMm SSs` / `MMm SSs` / `SSs`.
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

/// Render a [`crate::shape::RateSpec`] as `Nbps[/burst]` or `-`.
fn format_rate(rate: Option<&crate::shape::RateSpec>) -> String {
    match rate {
        None => "-".to_string(),
        Some(r) => match r.burst_rate_bps {
            Some(b) => format!("{}/burst {}", r.rate_bps, b),
            None => format!("{}", r.rate_bps),
        },
    }
}

fn disable_session(state: &ControlState, id_str: &str) -> String {
    let Some(id) = parse_session_id(id_str) else {
        return format!("Error: invalid session id {id_str:?}");
    };
    let Some(h) = state.registry.get(id) else {
        return format!("Error: no such session {id}");
    };
    if h.try_send(ControlCommand::Disconnect(DisconnectReason::AdminRequested)) {
        format!("Disconnect queued for session {id}")
    } else {
        format!("Error: session {id} could not be notified (queue full or exiting)")
    }
}

/// Force a TLS 1.3 `KeyUpdate` on a single session. Useful for soak
/// testing the rekey path: setting `request_peer = true` (`rekey
/// session <id> request`) makes the peer respond with its own
/// `KeyUpdate`, exercising both directions. TUN backend only — see
/// [`ControlCommand::Rekey`] for the kmod gate.
fn rekey_session(state: &ControlState, id_str: &str, request_peer: bool) -> String {
    let Some(id) = parse_session_id(id_str) else {
        return format!("Error: invalid session id {id_str:?}");
    };
    let Some(h) = state.registry.get(id) else {
        return format!("Error: no such session {id}");
    };
    if h.try_send(ControlCommand::Rekey { request_peer }) {
        let label = if request_peer {
            "Rekey queued (with update_requested) for session"
        } else {
            "Rekey queued for session"
        };
        format!("{label} {id}")
    } else {
        format!("Error: session {id} could not be notified (queue full or exiting)")
    }
}

fn shutdown(state: &ControlState) -> String {
    let _ = state.shutdown_tx.send(());
    "Shutting down".to_string()
}

fn parse_session_id(s: &str) -> Option<SessionId> {
    s.parse::<u64>().ok().map(SessionId::from_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_state() -> (ControlState, broadcast::Receiver<()>) {
        let (tx, rx) = broadcast::channel(1);
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
    fn empty_line_is_silent() {
        let (state, _rx) = test_state();
        assert_eq!(dispatch("", &state), "");
        assert_eq!(dispatch("   ", &state), "");
    }

    #[test]
    fn unknown_command_returns_error() {
        let (state, _rx) = test_state();
        assert!(dispatch("frobnicate", &state).starts_with("Error: unknown command"));
    }

    #[test]
    fn show_info_lists_uptime_and_threads() {
        let (state, _rx) = test_state();
        let out = dispatch("show info", &state);
        assert!(out.contains("version: "));
        assert!(out.contains("io_threads: 2"));
        assert!(out.contains("auth_threads: 1"));
        assert!(out.contains("active_sessions: 0"));
    }

    #[test]
    fn show_stat_includes_metric_names() {
        let (state, _rx) = test_state();
        let out = dispatch("show stat", &state);
        assert!(out.contains("sstp_connections_accepted:"));
    }

    #[test]
    fn show_sess_empty_then_one() {
        let (state, _rx) = test_state();
        assert_eq!(dispatch("show session", &state), "(no active sessions)");
        let id = SessionId::next();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, _session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        let listing = dispatch("show session", &state);
        assert!(listing.contains(&id.to_string()));
        assert!(listing.contains("127.0.0.1:5555"));
        let one = dispatch(&format!("show session {id}"), &state);
        assert!(one.contains("127.0.0.1:5555"));
    }

    #[test]
    fn disable_session_unknown_id_errors() {
        let (state, _rx) = test_state();
        assert!(dispatch("disable session 999999", &state).starts_with("Error: no such session"));
        assert!(
            dispatch("disable session notanid", &state).starts_with("Error: invalid session id")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disable_session_known_id_queues_disconnect() {
        let (state, _rx) = test_state();
        let id = SessionId::next();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, mut session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        let out = dispatch(&format!("disable session {id}"), &state);
        assert!(out.starts_with("Disconnect queued"));
        let cmd = session_rx.recv().await.expect("disconnect delivered");
        assert!(matches!(
            cmd,
            ControlCommand::Disconnect(DisconnectReason::AdminRequested)
        ));
    }

    #[test]
    fn rekey_session_unknown_id_errors() {
        let (state, _rx) = test_state();
        assert!(dispatch("rekey session 999999", &state).starts_with("Error: no such session"));
        assert!(dispatch("rekey session notanid", &state).starts_with("Error: invalid session id"));
        assert!(dispatch("rekey session", &state).starts_with("Error: usage:"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rekey_session_default_does_not_request_peer() {
        let (state, _rx) = test_state();
        let id = SessionId::next();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, mut session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        let out = dispatch(&format!("rekey session {id}"), &state);
        assert!(out.starts_with("Rekey queued"));
        assert!(!out.contains("update_requested"));
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
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, mut session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        let out = dispatch(&format!("rekey session {id} request"), &state);
        assert!(out.contains("update_requested"));
        let cmd = session_rx.recv().await.expect("rekey delivered");
        assert!(matches!(cmd, ControlCommand::Rekey { request_peer: true }));
    }

    #[test]
    fn rekey_session_garbage_fourth_token_is_unknown() {
        let (state, _rx) = test_state();
        let id = SessionId::next();
        let peer = "127.0.0.1:5555".parse().unwrap();
        let (handle, _session_rx) = crate::session::SessionHandle::for_test(id, peer);
        state.registry.register(handle);
        // anything other than literal "request" should fall through
        // to "unknown command" rather than silently rekeying.
        let out = dispatch(&format!("rekey session {id} bogus"), &state);
        assert!(out.starts_with("Error: unknown command"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_broadcasts() {
        let (state, mut rx) = test_state();
        let out = dispatch("shutdown", &state);
        assert_eq!(out, "Shutting down");
        rx.recv().await.expect("shutdown broadcast received");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unix_socket_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "sstp-ctl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("ctl.sock");
        let (state, shutdown_rx) = test_state();
        let sock_clone = sock.clone();
        let task = tokio::spawn(async move {
            let listener = bind(&sock_clone, None).unwrap();
            serve(sock_clone, listener, state, shutdown_rx)
                .await
                .unwrap();
        });
        // Wait for bind.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sock.exists(), "control socket did not appear");

        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream.write_all(b"show info\n").await.unwrap();
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.contains("io_threads:"), "got: {resp}");

        stream.write_all(b"shutdown\n").await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        assert!(!sock.exists(), "socket file should be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
