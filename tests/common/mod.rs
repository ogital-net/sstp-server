//! Shared helpers for `sstp-server`'s end-to-end integration tests.
//!
//! Integration tests live in `tests/<name>.rs` and each one is compiled as
//! its own crate. The `tests/common/` directory is included via
//! `mod common;` from each test file and does **not** itself become a
//! test target — see the Rust book chapter on integration tests.
//!
//! The pieces here are intentionally minimal: a self-signed TLS cert
//! generator, a free-port allocator, an RAII child-process guard, and a
//! dummy PAP-only RADIUS authenticator. Together they give the end-to-end
//! tests a deterministic, hermetic environment that does not depend on
//! any host configuration beyond `openssl` (which the dev container
//! installs unconditionally) and `sstpc` (which the dev container
//! installs in `post-create.sh`).

#![allow(dead_code)]

pub mod cert;
pub mod radius;
pub mod spawn;

use std::net::{SocketAddr, TcpListener, UdpSocket};

/// Reserve a free TCP port on `127.0.0.1` and immediately release it.
///
/// There is a tiny race between this function returning and the server
/// binding the same port, but in practice the kernel won't recycle the
/// port that fast and the tests retry the bind a couple of times anyway.
/// Good enough for an integration harness.
pub fn free_tcp_port() -> u16 {
    let sock = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral TCP");
    sock.local_addr().expect("local_addr").port()
}

/// Reserve a free UDP port on `127.0.0.1` and immediately release it.
pub fn free_udp_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP");
    sock.local_addr().expect("local_addr").port()
}

/// Convenience: an `127.0.0.1:<port>` socket address.
pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Per-test scratch directory under the cargo target dir. Auto-cleaned
/// on `Drop`. Uses `target/tmp/<test>-<pid>-<nanos>` so failing tests
/// can leave artefacts inspectable by running them with `--nocapture`
/// and `std::mem::forget(tmpdir)` from a debugger.
pub struct TempDir(std::path::PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock pre-epoch")
            .as_nanos();
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sstp-it-{label}-{pid}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir tempdir");
        Self(dir)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
