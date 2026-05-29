//! `sstp-server` binary entry point.
//!
//! Boots the `tokio` runtime(s), installs the `tracing` subscriber with a
//! non-blocking appender, supports `SIGHUP` TLS material reload, and
//! waits for `SIGINT`/`SIGTERM` to drain.
//!
//! The runtime topology mirrors the Architecture section in `CLAUDE.md`:
//! one `current_thread` `tokio` runtime per I/O worker thread (each with its
//! own `LocalSet`), and a separate multi-threaded `tokio` runtime for auth.
//! M0 wires up the threads and shutdown plumbing; the listener and session
//! tasks land in later milestones.

#![forbid(unsafe_op_in_unsafe_fn)]

mod auth;
mod cli;
mod control;
mod crypto;
mod kppp;
mod metrics;
mod net;
mod ppp;
mod privdrop;
mod session;
mod sstp;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tokio::task::{JoinHandle, LocalSet};
use tracing::{info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::auth::bridge::AuthBridge;
use crate::cli::{Config, LogFormat, ParseOutcome};
use crate::crypto::tls::SslContext;
use crate::session::{DisconnectReason, Registry};

const LOG_QUEUE_LINES: usize = 8192;
/// Grace period after broadcasting drain before forcibly tearing down
/// remaining sessions. Mirrors the typical PPP `Max-Terminate` budget
/// (RFC 1661 §4.1: 2 retransmits × 3 s) with headroom for TLS close.
const DRAIN_GRACE: Duration = Duration::from_secs(10);

/// Shared TLS server context handle. `RwLock` is the right primitive here:
/// the read path (`accept_loop` cloning the inner `SslContext`) is
/// uncontended in steady state and the critical section is just an
/// `SSL_CTX_up_ref` (one atomic increment). The write path (`SIGHUP`
/// reload) fires at most hourly in an ACME deployment and blocks accepts
/// for microseconds — invisible next to TLS handshake latency.
type SharedTlsContext = Arc<RwLock<SslContext>>;

fn main() -> ExitCode {
    // Developer convenience: populate env from `.env` if present. No-op in
    // production where systemd / Kubernetes inject env vars directly.
    let _ = dotenvy::dotenv();

    let (prog, parsed) = cli::parse_args(std::env::args_os());
    let config = match parsed {
        Ok(ParseOutcome::Run(c)) => c,
        Ok(ParseOutcome::Exit { message }) => {
            let _ = io::stdout().write_all(message.as_bytes());
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{prog}: {e}");
            eprintln!("Try '{prog} --help' for more information.");
            return ExitCode::from(2);
        }
    };

    let _log_guard = install_tracing(&config);

    info!(
        version = %cli::version_string(),
        listen = %config.listen,
        io_threads = config.io_threads.get(),
        auth_threads = config.auth_threads.get(),
        "sstp-server starting"
    );

    let exit = run(&config);

    info!("sstp-server stopped");
    exit
}

#[allow(clippy::too_many_lines)] // boot sequence: linear top-to-bottom, splitting hurts readability
fn run(config: &Config) -> ExitCode {
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let registry = Registry::new();
    let started = std::time::Instant::now();

    // ---- Phase 1: privileged setup (still as root if so launched) ----
    //
    // Everything that needs CAP_NET_BIND_SERVICE, root-readable key
    // files, or write access to `/run/` must happen here. After this
    // block we may `setuid` away to an unprivileged user; only
    // CAP_NET_ADMIN is retained, since per-session `/dev/ppp` ioctls
    // and netlink RTM_NEWADDR still need it.

    // Build the shared TLS server context once. `SslContext` is cheap to
    // clone (it's an `SSL_CTX_up_ref` under the hood) and is documented
    // thread-safe in AWS-LC, so each I/O worker / session gets its own
    // ref-counted handle without re-parsing the PEM files.
    // Restrict TLS 1.2 to AEAD ciphers only when the operator forced
    // the kernel data path. In that mode CBC-SHA suites would fail at
    // attach time anyway (kTLS only accelerates AEAD), so it's better
    // to reject the handshake up-front. Auto / tun / userspace stay
    // permissive — non-AEAD sessions transparently fall back to
    // userspace TLS.
    let aead_only = matches!(config.data_path, cli::DataPathMode::Kernel);
    let tls_ctx = match SslContext::server_from_pem(&config.cert, &config.key, aead_only) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, cert = %config.cert.display(), key = %config.key.display(), "failed to load TLS material");
            return ExitCode::from(1);
        }
    };
    let tls_ctx: SharedTlsContext = Arc::new(RwLock::new(tls_ctx));

    // RADIUS shared secret — env-only, never argv. Read here so the
    // server fails fast if it's missing, before any sockets are bound.
    let radius_secret = match std::env::var(cli::SSTP_RADIUS_SECRET) {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            tracing::error!(
                env_var = cli::SSTP_RADIUS_SECRET,
                "RADIUS shared secret not set; refusing to start"
            );
            return ExitCode::from(1);
        }
    };
    let radius_secret: std::sync::Arc<[u8]> = radius_secret.into();
    let radius_servers: Vec<(std::net::SocketAddr, std::sync::Arc<[u8]>)> = config
        .radius
        .iter()
        .map(|addr| (*addr, std::sync::Arc::clone(&radius_secret)))
        .collect();

    // Bind one SO_REUSEPORT std listener per I/O worker. Done now,
    // before any tokio runtime exists, so we can hand the listeners
    // to workers post-`privdrop` — they'd lack CAP_NET_BIND_SERVICE
    // by then.
    let mut listeners: Vec<std::net::TcpListener> = Vec::with_capacity(config.io_threads.get());
    for id in 0..config.io_threads.get() {
        match net::bind_reuseport_std(config.listen) {
            Ok(l) => listeners.push(l),
            Err(e) => {
                tracing::error!(worker = id, error = %e, listen = %config.listen, "failed to bind listener");
                return ExitCode::from(1);
            }
        }
    }

    // Resolve the drop target (if any) before opening the control
    // socket, so we can chown the socket file to the right owner
    // straight after `bind()`.
    let drop_identity = match resolve_drop_identity(config) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve --user/--group");
            return ExitCode::from(1);
        }
    };

    // Pre-bind the control socket (typically under `/run/`, which is
    // root-only writable). Chown to the drop target so the dropped
    // user can `unlink()` it on shutdown.
    let control_bound = match config.control_socket.as_deref() {
        Some(path) => {
            let owner = drop_identity.map(|id| (id.uid, id.gid));
            match control::bind(path, owner) {
                Ok(l) => Some((path.to_path_buf(), l)),
                Err(e) => {
                    tracing::error!(error = %e, path = %path.display(), "failed to bind control socket");
                    return ExitCode::from(1);
                }
            }
        }
        None => None,
    };

    // ---- Phase 2: drop privileges (still single-threaded) ----
    if let Some(id) = drop_identity {
        if let Err(e) = privdrop::drop_to(
            id,
            &[privdrop::CAP_NET_ADMIN, privdrop::CAP_SYS_NICE],
        ) {
            tracing::error!(error = %e, "privilege drop failed");
            return ExitCode::from(1);
        }
        info!(
            uid = id.uid,
            gid = id.gid,
            user = %privdrop::name_for_uid(id.uid),
            retained_caps = "CAP_NET_ADMIN,CAP_SYS_NICE",
            "dropped privileges"
        );
    }

    // Probe the SSTP kernel module once at startup so the operator
    // sees a single boot-time line about which data path is in play.
    // The per-session attach in `kppp::session::KpppSession::bring_up`
    // also gates on this, but the startup log is what an operator
    // looks for when troubleshooting.
    let effective_data_path = resolve_data_path_mode(config.data_path);

    // ---- Phase 3: spin up runtimes and worker threads ----

    // Auth runtime: multi-threaded so a slow RADIUS server can't head-of-line
    // block.
    let auth_runtime = Builder::new_multi_thread()
        .worker_threads(config.auth_threads.get())
        .thread_name("sstp-auth")
        .enable_all()
        .build()
        .expect("build auth runtime");

    let auth_bridge = match auth_runtime.block_on(AuthBridge::spawn(
        auth_runtime.handle(),
        "0.0.0.0:0".parse().expect("valid bind addr"),
        radius_servers,
    )) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to bind RADIUS client socket");
            return ExitCode::from(1);
        }
    };

    // I/O workers: one current_thread runtime per worker thread, each
    // with its own LocalSet. Each worker `adopt()`s the std listener
    // we pre-bound above.
    let mut workers = Vec::with_capacity(config.io_threads.get());
    for (id, std_listener) in listeners.into_iter().enumerate() {
        let rx = shutdown_tx.subscribe();
        let listen_addr = config.listen;
        let local_ip = config.local_ip;
        let data_path = effective_data_path;
        let worker_registry = registry.clone();
        let worker_shutdown = shutdown_tx.clone();
        let worker_tls = tls_ctx.clone();
        let worker_auth = auth_bridge.clone();
        let handle = thread::Builder::new()
            .name(format!("sstp-io-{id}"))
            .spawn(move || {
                io_worker_main(
                    id,
                    listen_addr,
                    std_listener,
                    rx,
                    worker_registry,
                    worker_shutdown,
                    worker_tls,
                    worker_auth,
                    local_ip,
                    data_path,
                );
            })
            .expect("spawn I/O worker");
        workers.push(handle);
    }

    let shutdown_for_signal = shutdown_tx.clone();
    let drain_registry = registry.clone();
    let reload_tls = tls_ctx.clone();
    let reload_cert = config.cert.clone();
    let reload_key = config.key.clone();
    let reload_aead_only = aead_only;
    let control_state = control::ControlState {
        registry: registry.clone(),
        shutdown_tx: shutdown_tx.clone(),
        started,
        io_threads: config.io_threads.get(),
        auth_threads: config.auth_threads.get(),
    };
    let control_shutdown_rx = shutdown_tx.subscribe();
    auth_runtime.block_on(async move {
        tokio::spawn(watch_sighup_reload_tls(
            reload_tls,
            reload_cert,
            reload_key,
            reload_aead_only,
        ));

        // Hand the pre-bound control socket to a runtime task. Failures
        // here can only come from `from_std`, which only fails if the
        // OS refuses to register the fd — extremely unusual.
        if let Some((path, listener)) = control_bound {
            tokio::spawn(async move {
                if let Err(e) =
                    control::serve(path, listener, control_state, control_shutdown_rx).await
                {
                    warn!(error = %e, "control socket failed");
                }
            });
        }
        wait_for_shutdown(shutdown_tx.subscribe()).await;
        // Phase 1: tell workers to stop accepting and tell every live
        // session to begin graceful teardown.
        let _ = shutdown_for_signal.send(());
        let initial = drain_registry.len();
        if initial > 0 {
            info!(active_sessions = initial, "draining sessions");
            drain_registry.broadcast_disconnect(DisconnectReason::ServerShutdown);
            // Phase 2: poll the registry until it empties or the grace
            // period elapses. Polling is fine — drain is a once-per-
            // process event and there are at most a few thousand
            // sessions in flight.
            let deadline = tokio::time::Instant::now() + DRAIN_GRACE;
            while !drain_registry.is_empty() && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let remaining = drain_registry.len();
            if remaining > 0 {
                warn!(
                    remaining,
                    "drain grace period elapsed; sessions will be dropped"
                );
            }
        }
    });

    auth_runtime.shutdown_background();
    for w in workers {
        if let Err(e) = w.join() {
            warn!(?e, "I/O worker panicked");
        }
    }

    ExitCode::SUCCESS
}

/// Resolve `--user` / `--group` into a [`privdrop::Identity`]. Returns
/// `Ok(None)` when no `--user` was supplied (privdrop is opt-in).
fn resolve_drop_identity(
    config: &Config,
) -> Result<Option<privdrop::Identity>, privdrop::DropError> {
    let Some(user) = config.drop_user.as_deref() else {
        return Ok(None);
    };
    let mut id = privdrop::lookup_user(user)?;
    if let Some(group) = config.drop_group.as_deref() {
        id.gid = privdrop::lookup_group(group)?;
    }
    Ok(Some(id))
}

/// Probe `/dev/sstp` once at boot and reconcile with the operator's
/// `--data-path` choice. Returns the effective mode the per-session
/// bring-up will pass to [`kppp::datapath::DataPath::open`].
///
/// `Auto` collapses to either `Auto` (kmod present) or `Userspace`
/// (kmod absent) so each session attach doesn't have to re-probe and
/// re-log. `Kernel` and `Userspace` pass through; explicit `Kernel`
/// with no kmod is logged as an error but not aborted here — the
/// per-session attach will fail loudly per connection, which is the
/// right granularity to alert on.
fn resolve_data_path_mode(requested: cli::DataPathMode) -> cli::DataPathMode {
    use cli::DataPathMode;
    use kppp::sstp_kmod::{self, KmodError};

    match (requested, sstp_kmod::probe()) {
        (DataPathMode::Tun, _) => {
            info!("data-path: tun (operator-selected; /dev/net/tun)");
            DataPathMode::Tun
        }
        (DataPathMode::Userspace, _) => {
            info!("data-path: userspace (operator-selected)");
            DataPathMode::Userspace
        }
        (DataPathMode::Kernel, Ok(())) => {
            info!("data-path: kernel (sstp kmod present at /dev/sstp)");
            DataPathMode::Kernel
        }
        (DataPathMode::Kernel, Err(e)) => {
            tracing::error!(error = %e, "data-path: kernel requested but /dev/sstp probe failed; per-session attaches will fail");
            DataPathMode::Kernel
        }
        (DataPathMode::Auto, Ok(())) => {
            info!(
                "data-path: auto (sstp kmod available; sessions use /dev/ppp by default and attempt kernel attach only when negotiated TLS is kTLS-compatible)"
            );
            DataPathMode::Auto
        }
        (DataPathMode::Auto, Err(KmodError::NotAvailable)) => {
            info!("data-path: tun (sstp kmod not loaded; falling back to /dev/net/tun)");
            DataPathMode::Tun
        }
        (DataPathMode::Auto, Err(e)) => {
            warn!(error = %e, "data-path: /dev/sstp present but unusable; falling back to TUN");
            DataPathMode::Tun
        }
    }
}

/// Promote the current thread to `SCHED_FIFO` priority 10. This
/// gives the I/O workers preemption authority over `SCHED_OTHER`
/// userspace (anything that's not RT-scheduled) so a busy host
/// can't introduce data-path jitter, while staying well below
/// the kernel's softirq RT threads (priority ~50) and the
/// `migration/N` kernel kthreads. Best-effort: we start as root
/// in normal deployments, but if `setpriority` is denied (no
/// `CAP_SYS_NICE`, `RLIMIT_RTPRIO`, container restrictions, etc.)
/// we log and keep going on the kernel's default scheduler.
fn set_io_thread_realtime(id: usize) {
    const SCHED_FIFO: libc::c_int = 1;
    const RT_PRIO: libc::c_int = 10;

    // SAFETY: `param` is a fully-initialized `sched_param`; passing
    // a null `pid_t` (0) means "the calling thread". The libc binding
    // takes a `*const sched_param`, which we provide.
    let rc = unsafe {
        let param = libc::sched_param {
            sched_priority: RT_PRIO,
        };
        libc::sched_setscheduler(0, SCHED_FIFO, &raw const param)
    };
    if rc == 0 {
        tracing::debug!(worker = id, prio = RT_PRIO, "I/O worker promoted to SCHED_FIFO");
    } else {
        let err = io::Error::last_os_error();
        tracing::warn!(
            worker = id,
            error = %err,
            "could not set I/O worker to SCHED_FIFO; staying on default scheduler"
        );
    }
}

#[allow(clippy::too_many_arguments)] // worker boot: every arg is essential per-worker context
fn io_worker_main(
    id: usize,
    listen: std::net::SocketAddr,
    std_listener: std::net::TcpListener,
    mut shutdown: broadcast::Receiver<()>,
    registry: Registry,
    shutdown_tx: broadcast::Sender<()>,
    tls_ctx: SharedTlsContext,
    auth_bridge: AuthBridge,
    local_ip: std::net::Ipv4Addr,
    data_path: cli::DataPathMode,
) {
    set_io_thread_realtime(id);
    let rt: Runtime = Builder::new_current_thread()
        .enable_all()
        .thread_name(format!("sstp-io-{id}"))
        .build()
        .expect("build I/O worker runtime");
    let local = LocalSet::new();
    local.block_on(&rt, async move {
        let listener = match net::adopt(std_listener) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(worker = id, error = %e, "failed to register listener with tokio");
                return;
            }
        };
        info!(worker = id, listen = %listen, "listener ready");
        accept_loop(
            id,
            listener,
            &mut shutdown,
            registry,
            shutdown_tx,
            tls_ctx,
            auth_bridge,
            local_ip,
            data_path,
        )
        .await;
    });
}

#[allow(clippy::too_many_arguments)] // accept loop: every arg is essential per-worker context
async fn accept_loop(
    worker_id: usize,
    listener: tokio::net::TcpListener,
    shutdown: &mut broadcast::Receiver<()>,
    registry: Registry,
    shutdown_tx: broadcast::Sender<()>,
    tls_ctx: SharedTlsContext,
    auth_bridge: AuthBridge,
    local_ip: std::net::Ipv4Addr,
    data_path: cli::DataPathMode,
) {
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    loop {
        // Reap completed tasks opportunistically so the Vec doesn't
        // grow without bound under steady-state load.
        tasks.retain(|h| !h.is_finished());

        tokio::select! {
            biased;
            _ = shutdown.recv() => {
                info!(
                    worker = worker_id,
                    in_flight = tasks.len(),
                    "accept loop draining"
                );
                break;
            }
            res = listener.accept() => match res {
                Ok((stream, peer)) => {
                    let (id, control_rx) = session::spawn_handle(&registry, peer);
                    let drain_rx = shutdown_tx.subscribe();
                    let registry = registry.clone();
                    let session_tls = tls_ctx
                        .read()
                        .expect("TLS context RwLock poisoned")
                        .clone();
                    let session_auth = auth_bridge.clone();
                    let handle = tokio::task::spawn_local(session::run(
                        stream, peer, id, registry, control_rx, drain_rx, session_tls, session_auth, local_ip, data_path,
                    ));
                    tasks.push(handle);
                }
                Err(e) => {
                    // Per-connection errors (EMFILE, ECONNABORTED) are
                    // transient; log and keep accepting.
                    warn!(worker = worker_id, error = %e, "accept failed");
                }
            }
        }
    }

    // Drain phase: wait for active session tasks to finish. Each one
    // already received the broadcast on its own `drain_rx`, so they
    // should be heading for the exit. We bound the wait at DRAIN_GRACE
    // so a stuck task can't keep us from exiting.
    if !tasks.is_empty() {
        let deadline = tokio::time::Instant::now() + DRAIN_GRACE;
        for h in tasks {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, h).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(worker = worker_id, error = %e, "session task panicked"),
                Err(_) => {
                    warn!(worker = worker_id, "drain timeout; abandoning session task");
                    break;
                }
            }
        }
    }
    info!(worker = worker_id, "accept loop exited");
}

async fn wait_for_shutdown(mut admin_rx: broadcast::Receiver<()>) {
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGTERM handler");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("received SIGINT, shutting down"),
        _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
        _ = admin_rx.recv() => info!("received control-socket shutdown, shutting down"),
    }
}

async fn watch_sighup_reload_tls(
    tls_ctx: SharedTlsContext,
    cert: PathBuf,
    key: PathBuf,
    aead_only: bool,
) {
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGHUP handler; TLS reload disabled");
            return;
        }
    };

    loop {
        sighup.recv().await;
        match SslContext::server_from_pem(&cert, &key, aead_only) {
            Ok(new_ctx) => {
                *tls_ctx.write().expect("TLS context RwLock poisoned") = new_ctx;
                info!(
                    cert = %cert.display(),
                    key = %key.display(),
                    "reloaded TLS material on SIGHUP; new connections use updated certificate"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    cert = %cert.display(),
                    key = %key.display(),
                    "SIGHUP TLS reload failed; keeping current certificate"
                );
            }
        }
    }
}

fn install_tracing(config: &Config) -> WorkerGuard {
    let env_filter = EnvFilter::builder()
        .with_default_directive(config.log_level.into())
        .from_env_lossy();

    let (writer, guard) = build_writer(config);

    let want_ansi = matches!(config.log_format, LogFormat::Text)
        || (matches!(config.log_format, LogFormat::Auto)
            && config.log_file.is_none()
            && io::stderr().is_terminal());
    let want_json = matches!(config.log_format, LogFormat::Json)
        || (matches!(config.log_format, LogFormat::Auto)
            && (config.log_file.is_some() || !io::stderr().is_terminal()));

    let registry = tracing_subscriber::registry().with(env_filter);
    if want_json {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(writer)
                    .with_current_span(true)
                    .with_span_list(false),
            )
            .init();
    } else {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(writer)
                    .with_ansi(want_ansi),
            )
            .init();
    }

    guard
}

fn build_writer(config: &Config) -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
    let builder = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(LOG_QUEUE_LINES);

    if let Some(path) = &config.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| {
                eprintln!("sstp-server: cannot open log file {}: {e}", path.display());
                std::process::exit(1);
            });
        builder.finish(file)
    } else {
        builder.finish(io::stderr())
    }
}
