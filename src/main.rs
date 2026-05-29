//! `sstp-server` binary entry point.
//!
//! Boots the `tokio` runtime(s), installs the `tracing` subscriber with a
//! non-blocking appender, and waits for `SIGINT`/`SIGTERM` to drain.
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
mod session;
mod sstp;

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
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

use crate::cli::{Config, LogFormat, ParseOutcome};
use crate::session::{DisconnectReason, Registry};

const LOG_QUEUE_LINES: usize = 8192;
/// Grace period after broadcasting drain before forcibly tearing down
/// remaining sessions. Mirrors the typical PPP `Max-Terminate` budget
/// (RFC 1661 §4.1: 2 retransmits × 3 s) with headroom for TLS close.
const DRAIN_GRACE: Duration = Duration::from_secs(10);

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

fn run(config: &Config) -> ExitCode {
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let registry = Registry::new();
    let started = std::time::Instant::now();

    // Auth runtime: multi-threaded so a slow RADIUS server can't head-of-line
    // block. M4 will spawn the actual auth tasks here.
    let auth_runtime = Builder::new_multi_thread()
        .worker_threads(config.auth_threads.get())
        .thread_name("sstp-auth")
        .enable_all()
        .build()
        .expect("build auth runtime");

    // I/O workers: one current_thread runtime per worker thread, each with
    // its own LocalSet. Every worker binds an SO_REUSEPORT listener on the
    // configured address; the kernel hashes incoming SYNs across them so
    // the worker that accepts a connection also owns it for life.
    let mut workers = Vec::with_capacity(config.io_threads.get());
    for id in 0..config.io_threads.get() {
        let rx = shutdown_tx.subscribe();
        let listen_addr = config.listen;
        let worker_registry = registry.clone();
        let worker_shutdown = shutdown_tx.clone();
        let handle = thread::Builder::new()
            .name(format!("sstp-io-{id}"))
            .spawn(move || io_worker_main(id, listen_addr, rx, worker_registry, worker_shutdown))
            .expect("spawn I/O worker");
        workers.push(handle);
    }

    let shutdown_for_signal = shutdown_tx.clone();
    let drain_registry = registry.clone();
    let control_socket_path = config.control_socket.clone();
    let control_state = control::ControlState {
        registry: registry.clone(),
        shutdown_tx: shutdown_tx.clone(),
        started,
        io_threads: config.io_threads.get(),
        auth_threads: config.auth_threads.get(),
    };
    let control_shutdown_rx = shutdown_tx.subscribe();
    auth_runtime.block_on(async move {
        // Spawn the control socket if configured. Failures to bind are
        // logged but do not abort the server — the data plane keeps
        // running.
        if let Some(path) = control_socket_path {
            tokio::spawn(async move {
                if let Err(e) = control::serve(&path, control_state, control_shutdown_rx).await {
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

fn io_worker_main(
    id: usize,
    listen: std::net::SocketAddr,
    mut shutdown: broadcast::Receiver<()>,
    registry: Registry,
    shutdown_tx: broadcast::Sender<()>,
) {
    let rt: Runtime = Builder::new_current_thread()
        .enable_all()
        .thread_name(format!("sstp-io-{id}"))
        .build()
        .expect("build I/O worker runtime");
    let local = LocalSet::new();
    local.block_on(&rt, async move {
        let listener = match net::bind_reuseport(listen) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(worker = id, error = %e, "failed to bind listener");
                return;
            }
        };
        info!(worker = id, listen = %listen, "listener ready");
        accept_loop(id, listener, &mut shutdown, registry, shutdown_tx).await;
    });
}

async fn accept_loop(
    worker_id: usize,
    listener: tokio::net::TcpListener,
    shutdown: &mut broadcast::Receiver<()>,
    registry: Registry,
    shutdown_tx: broadcast::Sender<()>,
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
                    let handle = tokio::task::spawn_local(session::run(
                        stream, peer, id, registry, control_rx, drain_rx,
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
