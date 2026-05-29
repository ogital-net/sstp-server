//! End-to-end integration tests against the `sstp-server` binary.
//!
//! The fixtures bring up:
//!   1. a self-signed TLS cert,
//!   2. a dummy RADIUS PAP authenticator that accepts a single
//!      hardcoded credential and replies with a `Framed-IP-Address`,
//!   3. the `sstp-server` binary itself, configured to listen on a
//!      free TCP port and forward auth to the dummy RADIUS.
//!
//! The first test (`tls_handshake_smoke`) drives an in-process TLS
//! client at the server and asserts that the TLS handshake completes
//! and the server accepts the connection. This is the regression
//! gate for the listener / TLS-acceptor path and runs everywhere
//! `openssl` and a built binary are available.
//!
//! The second test (`sstpc_pap_login`) spawns the upstream
//! `sstp-client` binary against the server with PAP credentials.
//! Because the server's session driver (M6) does not yet implement
//! the SSTP HTTPS preamble or the PPP/RADIUS bridge, `sstpc` is
//! expected to fail at the HTTP layer for now — the test asserts
//! that the *connection-acceptance* path works and records the
//! current bar so a future driver implementation graduates this to
//! a full PAP success assertion. See `CLAUDE.md` §M6 "MVP roadmap".
//!
//! Both tests skip cleanly when their prerequisites are missing
//! (`sstpc` not on `PATH`, `/dev/ppp` not present, …) so `cargo
//! test` is hermetic in any environment.

mod common;

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::cert::gen_self_signed;
use common::radius::{Credential, DummyRadius, PapOutcome};
use common::spawn::ServerBuilder;
use common::{free_tcp_port, free_udp_port, loopback, TempDir};

const TEST_USER: &str = "alice";
const TEST_PASS: &[u8] = b"correct horse battery";
const TEST_FRAMED_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 42);
const SERVER_READY: Duration = Duration::from_secs(5);

fn build_credential() -> Credential {
    Credential {
        username: TEST_USER.to_string(),
        password: TEST_PASS.to_vec(),
        framed_ip: TEST_FRAMED_IP,
    }
}

/// Probe whether `sstpc` is runnable in this environment. Returns a
/// human-readable reason string on skip, or `None` if everything is
/// in place.
fn sstpc_skip_reason() -> Option<String> {
    if which("sstpc").is_none() {
        return Some("sstpc not on PATH".into());
    }
    // sstpc spawns pppd, which needs /dev/ppp and CAP_NET_ADMIN. In a
    // typical dev container neither is available; skip rather than
    // hard-fail.
    if !std::path::Path::new("/dev/ppp").exists() {
        return Some("/dev/ppp not present (need PPP kmod loaded)".into());
    }
    // EUID 0 is the simplest portable check; CAP_NET_ADMIN is a
    // superset of "is root" for our purposes.
    // SAFETY: getuid() has no preconditions and is signal-safe.
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        return Some(format!("not running as root (uid={uid}); pppd needs CAP_NET_ADMIN"));
    }
    None
}

fn which(prog: &str) -> Option<std::path::PathBuf> {
    // Fallback to well-known install locations. The VS Code test
    // runner inherits a stripped PATH that often omits
    // `~/.local/bin` and `/opt/*/sbin`, so the shell-level `which`
    // succeeds while the in-test probe used to skip. Check the
    // dev-container's canonical sstpc paths directly.
    const FALLBACKS: &[&str] = &[
        "/home/vscode/.local/bin",
        "/opt/sstp-client/sbin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/sbin",
    ];
    // PATH first, so an explicit override wins.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(prog);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    for dir in FALLBACKS {
        let cand = std::path::Path::new(dir).join(prog);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Smoke test: TCP listener accepts a connection and the TLS
/// acceptor completes the handshake against an `openssl s_client`.
/// Runs without root.
///
/// Today the session task in `src/session.rs` terminates TLS but
/// does not yet drive the SSTP HTTPS preamble or the PPP/RADIUS
/// bridge (see `CLAUDE.md` §M6 MVP roadmap: M6b onward). So this
/// test currently asserts what works: TLS handshake completes
/// server-side. When the SSTP preamble is wired in (M6b), this
/// assertion should graduate to checking that the server emits the
/// `HTTP/1.1 200` line and transitions into SSTP framing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_smoke() {
    let tmp = TempDir::new("tls");
    let pem = gen_self_signed(tmp.path());

    let radius_port = free_udp_port();
    let radius = DummyRadius::start_on(radius_port, build_credential()).await;

    let sstp_port = free_tcp_port();
    let listen = loopback(sstp_port);
    let server = ServerBuilder::new(listen, &pem.cert, &pem.key)
        .radius(radius.addr)
        .spawn(SERVER_READY);

    // Use `openssl s_client` as a convenient way to push a real
    // ClientHello at the server. We don't assert on its exit status
    // because the server currently tears the TCP connection down
    // mid-handshake on purpose (M6 scaffold).
    let _ = tokio::task::spawn_blocking(move || {
        Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("127.0.0.1:{sstp_port}"),
                "-servername",
                "localhost",
                "-no_ign_eof",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("invoke openssl s_client")
    })
    .await
    .expect("s_client join");

    // The server should log a successful TLS handshake. The
    // readiness-probe connection (`TcpStream::connect_timeout` inside
    // `ServerBuilder::spawn`) only opens TCP and closes — that
    // triggers a "TLS handshake failed" line for the probe — so we
    // wait specifically for the "TLS handshake completed" line that
    // can only come from a peer that actually sent a ClientHello.
    let saw_handshake = server
        .wait_for_log("TLS handshake completed", Duration::from_secs(5))
        .is_some();
    assert!(
        saw_handshake,
        "expected to see 'TLS handshake completed' in server logs after openssl ClientHello.\n\
         server logs:\n{}",
        server.drain_logs().join("\n")
    );

    // RADIUS should not have been reached yet — the session driver
    // does not implement auth, so this is a forward-looking guard:
    // the day the auth bridge is wired up, this assertion will fire
    // and the test graduates to checking that we did reach RADIUS.
    let seen = radius.seen();
    assert!(
        seen.is_empty(),
        "dummy RADIUS unexpectedly received {} requests; \
         is the session driver now reaching auth? Time to upgrade this assertion.\n\
         seen: {seen:#?}",
        seen.len()
    );
}

/// End-to-end test driving the upstream `sstpc` client against the
/// server. Skipped if prerequisites (sstpc, /dev/ppp, root) are not
/// available — see [`sstpc_skip_reason`].
///
/// **M6h graduated assertions.** When prerequisites are present this
/// drives the full PAP path end-to-end and checks:
///   * the dummy RADIUS authenticator received exactly one
///     `Access-Request` with `User-Name=alice` and a PAP outcome of
///     `Match`;
///   * the server logged "kernel PPP unit attached" (M6g brought up
///     `pppN` via `/dev/ppp` + netlink);
///   * the resulting netdev exists and carries the
///     `Framed-IP-Address` as its P2P peer.
///
/// We deliberately *do not* assert `sstpc`'s exit status: the harness
/// SIGKILLs it once the kernel PPP unit appears, so its exit will be
/// signal-terminated. Asserting a clean exit would require driving
/// `sstpc`'s own teardown path, which is outside the SSTP server's
/// responsibility.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sstpc_pap_login() {
    if let Some(reason) = sstpc_skip_reason() {
        eprintln!("SKIP sstpc_pap_login: {reason}");
        return;
    }

    let tmp = TempDir::new("sstpc");
    let pem = gen_self_signed(tmp.path());

    let radius_port = free_udp_port();
    let radius = DummyRadius::start_on(radius_port, build_credential()).await;

    let sstp_port = free_tcp_port();
    let listen = loopback(sstp_port);
    let server = ServerBuilder::new(listen, &pem.cert, &pem.key)
        .radius(radius.addr)
        .spawn(SERVER_READY);

    // sstpc usage:
    //   sstpc [opts] <hostname> [pppd opts]
    // `noauth` disables peer-auth requirements; `user`/`password`
    // give pppd the PAP credentials it offers when the server
    // proposes Auth-Protocol=PAP.
    let host = format!("127.0.0.1:{sstp_port}");
    let sstpc = tokio::task::spawn_blocking(move || {
        Command::new("sstpc")
            .args([
                "--cert-warn",
                "--save-server-route",
                "--log-stderr",
                "--log-level",
                "4",
                &host,
                "noauth",
                "noipdefault",
                "nodefaultroute",
                "user",
                TEST_USER,
                "password",
            ])
            .arg(String::from_utf8_lossy(TEST_PASS).into_owned())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sstpc")
    });
    let mut child = sstpc.await.expect("sstpc spawn join");

    // The decisive event is M6g's "kernel PPP unit attached" log
    // line, emitted once IPCP converges and the netlink bring-up
    // succeeds. Give the full PAP + IPCP round-trip a generous
    // window — pppd is slow to start under load.
    let attach_line = server.wait_for_log("kernel PPP unit attached", Duration::from_secs(15));

    // Reap sstpc unconditionally so we don't leak the child if an
    // assertion below fires.
    let _ = child.kill();
    let out = child.wait_with_output().expect("reap sstpc");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    let attach_line = attach_line.unwrap_or_else(|| {
        panic!(
            "did not see 'kernel PPP unit attached' within 15s.\n\
             sstpc stdout:\n{stdout}\nsstpc stderr:\n{stderr}\n\
             server logs:\n{}",
            server.drain_logs().join("\n")
        )
    });

    // Pull the netdev name out of the structured log so the
    // post-condition check targets the exact interface this test
    // brought up (avoids racing against parallel test runs that
    // might also be creating `pppN` units).
    let ifname = extract_kv(&attach_line, "ifname").unwrap_or_else(|| {
        panic!("no 'ifname=' field in attach log line: {attach_line}")
    });

    // RADIUS-side post-conditions: exactly one Access-Request, for
    // our user, with a matching PAP password.
    let seen = radius.seen();
    assert_eq!(
        seen.len(),
        1,
        "expected exactly one RADIUS request; got {}: {seen:#?}",
        seen.len()
    );
    let req = &seen[0];
    assert_eq!(
        req.username.as_deref(),
        Some(TEST_USER),
        "RADIUS User-Name mismatch: {req:#?}"
    );
    assert!(
        matches!(req.pap_outcome, Some(PapOutcome::Match)),
        "RADIUS PAP outcome != Match: {req:#?}"
    );

    // Kernel-side post-condition: the netdev the server logged
    // exists and carries the Framed-IP-Address as its P2P peer.
    let ip_out = Command::new("ip")
        .args(["-o", "addr", "show", "dev", &ifname])
        .output()
        .expect("invoke `ip addr show`");
    assert!(
        ip_out.status.success(),
        "`ip addr show {ifname}` failed: {:?}",
        String::from_utf8_lossy(&ip_out.stderr)
    );
    let addr_str = String::from_utf8_lossy(&ip_out.stdout);
    let needle = format!("peer {TEST_FRAMED_IP}");
    assert!(
        addr_str.contains(&needle),
        "expected `{needle}` on {ifname}, got:\n{addr_str}"
    );
}

/// Extract `key=value` from a tracing-formatted log line. Returns the
/// trimmed value (terminated by whitespace) or `None` if the key is
/// absent. Used by the e2e test to pluck `ifname=ppp0` out of the
/// "kernel PPP unit attached" line.
fn extract_kv(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// SSTP HTTPS preamble (MS-SSTP §3.2.4.1 / §4.1): send the canonical
/// `SSTP_DUPLEX_POST` request over TLS and assert the server replies
/// with `HTTP/1.1 200 OK` carrying the spec-mandated headers. Uses
/// `openssl s_client -quiet` as a thin TLS pipe so this test stays
/// hermetic — no `sstpc`, no `/dev/ppp`, no root required.
///
/// When the SSTP state machine drive (M6c) lands, this test should
/// graduate to additionally writing a `Call-Connect-Request` after
/// the `200` and asserting a `Call-Connect-Ack` comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sstp_https_preamble() {
    let tmp = TempDir::new("preamble");
    let pem = gen_self_signed(tmp.path());

    let radius_port = free_udp_port();
    let radius = DummyRadius::start_on(radius_port, build_credential()).await;

    let sstp_port = free_tcp_port();
    let listen = loopback(sstp_port);
    let server = ServerBuilder::new(listen, &pem.cert, &pem.key)
        .radius(radius.addr)
        .spawn(SERVER_READY);

    let target = format!("127.0.0.1:{sstp_port}");
    let request = b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    SSTPCORRELATIONID: {DEADBEEF-1234-5678-9ABC-DEF012345678}\r\n\
                    Content-Length: 18446744073709551615\r\n\
                    \r\n";

    let output = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let mut child = Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &target,
                "-servername",
                "localhost",
                "-quiet",   // suppress session banner so stdout is pure app data
                "-ign_eof", // keep reading after stdin closes
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn openssl s_client");
        child
            .stdin
            .as_mut()
            .expect("openssl stdin")
            .write_all(request)
            .expect("write SSTP_DUPLEX_POST");
        // Drop stdin so openssl knows we're done sending. The server
        // is supposed to keep the connection open after the 200, so
        // openssl will still be reading; cap the wait.
        drop(child.stdin.take());
        std::thread::sleep(Duration::from_secs(2));
        let _ = child.kill();
        child.wait_with_output().expect("reap openssl")
    })
    .await
    .expect("openssl join");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HTTP/1.1 200 OK\r\n"),
        "expected '200 OK' from server preamble; got:\n{stdout}\n\
         server logs:\n{}",
        server.drain_logs().join("\n")
    );
    assert!(
        stdout.contains("Content-Length: 18446744073709551615\r\n"),
        "missing ULONGLONG_MAX Content-Length in 200 response:\n{stdout}"
    );
    assert!(
        stdout.contains("Server: Microsoft-HTTPAPI/2.0\r\n"),
        "missing canonical Server header in 200 response:\n{stdout}"
    );

    let saw_preamble = server
        .wait_for_log("SSTP HTTPS preamble accepted", Duration::from_secs(2))
        .is_some();
    assert!(
        saw_preamble,
        "expected 'SSTP HTTPS preamble accepted' in server logs.\n\
         server logs:\n{}",
        server.drain_logs().join("\n")
    );

    // Auth bridge still not wired (M6e); RADIUS must not have been
    // touched by the preamble alone.
    assert!(
        radius.seen().is_empty(),
        "preamble path unexpectedly reached RADIUS"
    );
}
