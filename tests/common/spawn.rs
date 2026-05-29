//! Spawn `sstp-server` (the binary under test) as a child process.
//!
//! Uses the `CARGO_BIN_EXE_<name>` env var that cargo sets for
//! integration tests — see [cargo book §Environment Variables].
//! The returned [`ServerHandle`] kills the child on drop, so test
//! failures don't leak processes.
//!
//! [cargo book §Environment Variables]:
//!     https://doc.rust-lang.org/cargo/reference/environment-variables.html

use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Path to the freshly-built `sstp-server` binary. Cargo sets this
/// for integration tests automatically.
pub fn server_binary() -> &'static str {
    env!("CARGO_BIN_EXE_sstp-server")
}

/// Builder for an `sstp-server` child process.
pub struct ServerBuilder {
    listen: SocketAddr,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    radius: Vec<SocketAddr>,
    radius_secret: Vec<u8>,
    no_control_socket: bool,
    verbose: u8,
    extra_args: Vec<OsString>,
}

impl ServerBuilder {
    pub fn new(listen: SocketAddr, cert: &Path, key: &Path) -> Self {
        Self {
            listen,
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            radius: Vec::new(),
            radius_secret: b"testing123".to_vec(),
            no_control_socket: true,
            verbose: 2, // -vv: debug-level, surfaces control-plane state
            extra_args: Vec::new(),
        }
    }

    pub fn radius(mut self, addr: SocketAddr) -> Self {
        self.radius.push(addr);
        self
    }

    pub fn radius_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.radius_secret = secret.into();
        self
    }

    pub fn verbose(mut self, v: u8) -> Self {
        self.verbose = v;
        self
    }

    /// Spawn the child. Waits up to `ready_timeout` for the listener
    /// to start accepting on the configured port; returns once a TCP
    /// connect succeeds. Panics on timeout.
    pub fn spawn(self, ready_timeout: Duration) -> ServerHandle {
        let mut cmd = Command::new(server_binary());
        cmd.arg("--listen").arg(self.listen.to_string());
        cmd.arg("--cert").arg(&self.cert);
        cmd.arg("--key").arg(&self.key);
        for r in &self.radius {
            cmd.arg("--radius").arg(r.to_string());
        }
        if self.no_control_socket {
            cmd.arg("--no-control-socket");
        }
        for _ in 0..self.verbose {
            cmd.arg("-v");
        }
        cmd.args(&self.extra_args);

        // Secrets travel via env, never argv.
        cmd.env("SSTP_RADIUS_SECRET", String::from_utf8_lossy(&self.radius_secret).into_owned());
        // Force text logs so the line-oriented reader thread works
        // regardless of whether the test runner is a TTY.
        cmd.env("RUST_LOG", "sstp_server=debug,info");

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn sstp-server binary");

        let (log_tx, log_rx) = mpsc::channel::<String>();

        // Stream stderr (where tracing writes) to both the test's
        // captured output and an in-process buffer so tests can
        // grep for log lines.
        let stderr = child.stderr.take().expect("stderr piped");
        let log_tx_err = log_tx.clone();
        let err_thread = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("[sstp-server] {line}");
                let _ = log_tx_err.send(line);
            }
        });

        // Same for stdout (in case the binary ever logs there).
        let stdout = child.stdout.take().expect("stdout piped");
        let out_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("[sstp-server] {line}");
                let _ = log_tx.send(line);
            }
        });

        // Wait for the listener to be ready: poll TCP connect until
        // it succeeds. Tighter than parsing logs and not subject to
        // log-format drift.
        let deadline = Instant::now() + ready_timeout;
        loop {
            if let Ok(s) = TcpStream::connect_timeout(&self.listen, Duration::from_millis(200)) {
                drop(s);
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!(
                    "sstp-server did not start accepting on {} within {:?}",
                    self.listen, ready_timeout
                );
            }
            thread::sleep(Duration::from_millis(50));
        }

        ServerHandle {
            child: Some(child),
            log_rx,
            _threads: (err_thread, out_thread),
            listen: self.listen,
        }
    }
}

pub struct ServerHandle {
    child: Option<Child>,
    log_rx: mpsc::Receiver<String>,
    _threads: (thread::JoinHandle<()>, thread::JoinHandle<()>),
    pub listen: SocketAddr,
}

impl ServerHandle {
    /// Drain currently-buffered log lines without blocking.
    pub fn drain_logs(&self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(line) = self.log_rx.try_recv() {
            out.push(line);
        }
        out
    }

    /// Block (up to `timeout`) for a log line matching `needle`. Returns
    /// the matching line, or `None` on timeout.
    pub fn wait_for_log(&self, needle: &str, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.log_rx.recv_timeout(remaining) {
                Ok(line) => {
                    if line.contains(needle) {
                        return Some(line);
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // SIGKILL is fine — this is a test harness and the binary
            // has no on-disk state that needs cleanup.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
