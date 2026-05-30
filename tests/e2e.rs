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
use common::{TempDir, free_tcp_port, free_udp_port, loopback};

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
        return Some(format!(
            "not running as root (uid={uid}); pppd needs CAP_NET_ADMIN"
        ));
    }
    None
}

fn which(prog: &str) -> Option<std::path::PathBuf> {
    // Fallback to well-known install locations. Under `sudo` PATH is
    // sanitised (secure_path), so the shell-level `which` succeeds
    // while a bare `Command::new("sstpc")` fails with ENOENT. Resolve
    // up front and let callers pass the absolute path to `Command`.
    let mut fallbacks: Vec<std::path::PathBuf> = Vec::new();
    // `sudo -E` preserves HOME; without -E it's root's. Try both the
    // invoking user's home (via SUDO_USER) and $HOME.
    if let Some(home) = std::env::var_os("HOME") {
        fallbacks.push(std::path::PathBuf::from(home).join(".local/bin"));
    }
    if let Some(user) = std::env::var_os("SUDO_USER") {
        fallbacks.push(
            std::path::PathBuf::from("/home")
                .join(user)
                .join(".local/bin"),
        );
    }
    for d in [
        "/home/vscode/.local/bin",
        "/opt/sstp-client/sbin",
        "/opt/sstp-client/bin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/sbin",
    ] {
        fallbacks.push(std::path::PathBuf::from(d));
    }
    // PATH first, so an explicit override wins.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(prog);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    for dir in fallbacks {
        let cand = dir.join(prog);
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
    //   sstpc <sstp-options> <hostname> [[--] <pppd-options>]
    // The sstpc binary takes `--user` / `--password` for the SSTP
    // auth pass-through; pppd then negotiates PAP using credentials
    // supplied via its own `user`/`password` directives. We pass
    // both. `--priv-dir` overrides the compiled-in default
    // (`$PREFIX/var/run/sstpc`) which the dev-container's install
    // never created; point it at our scratch dir.
    let host = format!("127.0.0.1:{sstp_port}");
    let sstpc_bin = which("sstpc").expect("sstpc resolved by skip probe");
    let priv_dir = tmp.path().join("sstpc-priv");
    std::fs::create_dir_all(&priv_dir).expect("mkdir sstpc priv-dir");
    let priv_dir_str = priv_dir.to_string_lossy().into_owned();
    let pass_str = String::from_utf8_lossy(TEST_PASS).into_owned();
    let sstpc = tokio::task::spawn_blocking(move || {
        Command::new(&sstpc_bin)
            .args([
                "--cert-warn",
                "--save-server-route",
                "--log-stderr",
                "--log-level",
                "4",
                "--priv-dir",
                &priv_dir_str,
                "--user",
                TEST_USER,
                "--password",
                &pass_str,
                &host,
                "--",
                "noauth",
                "noipdefault",
                "nodefaultroute",
                "user",
                TEST_USER,
                "password",
                &pass_str,
            ])
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
    // window — pppd is slow to start under load. Use
    // `collect_logs_until` (not `wait_for_log`) so we also retain
    // the kmod-fallback line that arrives moments before attach.
    let pre_attach_logs =
        server.collect_logs_until("kernel PPP unit attached", Duration::from_secs(15));

    let attach_line = match pre_attach_logs.as_ref().and_then(|v| v.last()).cloned() {
        Some(line) => line,
        None => {
            // Reap before panicking so we don't leak the child.
            let _ = child.kill();
            let out = child.wait_with_output().expect("reap sstpc");
            panic!(
                "did not see 'kernel PPP unit attached' within 15s.\n\
                 sstpc stdout:\n{}\nsstpc stderr:\n{}\n\
                 server logs:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                server.drain_logs().join("\n")
            );
        }
    };
    let pre_attach_logs = pre_attach_logs.expect("checked above");

    // Pull the netdev name out of the structured log so the
    // post-condition check targets the exact interface this test
    // brought up (avoids racing against parallel test runs that
    // might also be creating `pppN` units).
    let ifname = extract_kv(&attach_line, "ifname").unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no 'ifname=' field in attach log line: {attach_line}")
    });

    // Kernel-side post-condition: the netdev the server logged
    // exists and carries the Framed-IP-Address as its P2P peer.
    // **Do this before reaping sstpc** — closing the TLS socket
    // tears the session down, which removes `pppN` instantly.
    let ip_bin = which("ip").unwrap_or_else(|| std::path::PathBuf::from("/usr/sbin/ip"));
    let ip_out = Command::new(&ip_bin)
        .args(["-o", "addr", "show", "dev", &ifname])
        .output()
        .expect("invoke `ip addr show`");

    // Half-duplex traffic check: push a single ICMP echo from the
    // sstpc-side `pppN` toward the server's tunnel endpoint, then
    // assert the server's `pppN` RX counter grew. This proves the
    // client→server data direction actually carries IP frames
    // end-to-end (sstpc → TLS → SSTP demux → KpppSession::write_frame
    // → kernel pppN). Server→client direction is *not* tested here
    // because, without the sstp kmod + kTLS, the kernel never hands
    // TX frames back to the unit-fd reader (mainline ppp_generic
    // dispatches them through channels) — see session.rs.
    //
    // Done *before* reaping sstpc for the same reason as the addr
    // assertion above: closing TLS tears `pppN` down.
    let traffic_result = exercise_client_to_server_traffic(&ip_bin, &ifname);

    // Capture probe-path log evidence. With /dev/sstp loaded and a
    // kTLS-compatible cipher, Auto escalates to Kernel and we
    // expect the kTLS install + kmod attach to succeed. Without
    // the kmod loaded (or with a kTLS-incompatible cipher), Auto
    // resolves to Tun.
    let kmod_present = std::path::Path::new("/dev/sstp").exists();
    let kmod_attach_succeeded = pre_attach_logs
        .iter()
        .any(|l| l.contains("kTLS installed on TCP socket"));
    let tun_fallback_taken = pre_attach_logs
        .iter()
        .any(|l| l.contains("falling back to TUN"));

    // Now safe to reap sstpc.
    let _ = child.kill();
    let _ = child.wait_with_output().expect("reap sstpc");

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

    // Validate the netdev assertions captured earlier.
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

    // Probe path: when /dev/sstp is loaded and the negotiated TLS
    // session is kTLS-compatible (the default with our self-signed
    // RSA cert: TLS 1.3 AES-GCM), Auto escalates to Kernel mode.
    // Assert the kTLS install ran and we did *not* take the TUN
    // fallback. The `ifname` should be `pppN`, not `tunN`.
    if kmod_present {
        assert!(
            kmod_attach_succeeded,
            "/dev/sstp exists but kTLS install was never attempted;\n\
             pre-attach logs:\n{}",
            pre_attach_logs.join("\n")
        );
        assert!(
            !tun_fallback_taken,
            "kmod attach should have succeeded with kTLS, but the server fell back to TUN;\n\
             pre-attach logs:\n{}",
            pre_attach_logs.join("\n")
        );
        assert!(
            ifname.starts_with("ppp"),
            "expected kernel PPP unit (pppN), got `{ifname}`"
        );
    }

    // Traffic observation: push an ICMP echo from the client and
    // measure the server-side interface counters. Both kernel-mode
    // (sstp kmod + kTLS, ifname=pppN) and TUN-mode (ifname=tunN)
    // are real data paths and should bump `server rx_bytes`.
    let kernel_path_active = ifname.starts_with("ppp") && kmod_attach_succeeded;
    let tun_path_active = ifname.starts_with("tun");
    match traffic_result {
        Ok(TrafficObservation {
            server_rx_before,
            server_rx_after,
            server_tx_before,
            server_tx_after,
            client_ifname,
        }) => {
            let path_label = if kernel_path_active {
                "kernel (sstp kmod + kTLS)"
            } else {
                assert!(tun_path_active, "unexpected ifname `{ifname}`");
                "TUN"
            };
            eprintln!(
                "traffic observation ({path_label}):\n  \
                 client `{client_ifname}` -> server `{ifname}`:\n  \
                 server rx_bytes: {server_rx_before} -> {server_rx_after} (+{})\n  \
                 server tx_bytes: {server_tx_before} -> {server_tx_after} (+{})",
                server_rx_after.saturating_sub(server_rx_before),
                server_tx_after.saturating_sub(server_tx_before),
            );
            if kernel_path_active || tun_path_active {
                assert!(
                    server_rx_after > server_rx_before,
                    "{path_label} data path active but server rx_bytes did not grow \
                     ({server_rx_before} -> {server_rx_after}); data path \
                     regression"
                );
            }
        }
        Err(reason) => {
            // Same skip policy as before: missing client pppN is
            // outside our control (pppd IPCP), genuine errors panic.
            assert!(
                reason.contains("client-side"),
                "traffic check failed: {reason}\nserver logs:\n{}",
                server.drain_logs().join("\n")
            );
            eprintln!("SKIP traffic observation: {reason}");
        }
    }
}

/// Outcome of the half-duplex traffic exercise. See
/// [`exercise_client_to_server_traffic`]. v0.1 records both
/// directions because neither one moves data through the tunnel
/// without the sstp kmod + kTLS (see CLAUDE.md "Data plane").
struct TrafficObservation {
    server_rx_before: u64,
    server_rx_after: u64,
    server_tx_before: u64,
    server_tx_after: u64,
    client_ifname: String,
}

/// Find the sstpc-side `pppN` (the one whose local address is
/// `TEST_FRAMED_IP`), snapshot the *server*-side `pppN` rx_bytes
/// counter, fire a single `ping` from the client interface to the
/// server endpoint, then re-read the counter. Returns the before/
/// after pair on success, or a descriptive error string explaining
/// why the exercise could not be performed (caller decides whether
/// to skip or fail).
fn exercise_client_to_server_traffic(
    ip_bin: &std::path::Path,
    server_ifname: &str,
) -> Result<TrafficObservation, String> {
    // Wait up to ~5s for pppd (on the sstpc side) to bring up its
    // own pppN with the negotiated Framed-IP-Address. IPCP completes
    // on the server side before pppd finishes its own kernel-side
    // bring-up, so the client interface usually appears a few
    // hundred milliseconds after our "kernel PPP unit attached" log.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let client_ifname = loop {
        if let Some(name) = find_ifname_with_local_addr(ip_bin, TEST_FRAMED_IP) {
            // Don't return our *own* server-side interface even in
            // the (impossible-by-construction) case the local addr
            // matched there.
            if name != server_ifname {
                break name;
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "client-side pppN with local addr {TEST_FRAMED_IP} did not \
                 appear within 5s (pppd may have failed IPCP)"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let rx_before = read_rx_bytes(ip_bin, server_ifname)
        .ok_or_else(|| format!("could not read rx_bytes on server-side `{server_ifname}`"))?;
    let tx_before = read_tx_bytes(ip_bin, server_ifname)
        .ok_or_else(|| format!("could not read tx_bytes on server-side `{server_ifname}`"))?;

    // -I binds source IP / outgoing interface so the packet is
    // forced out the client pppN regardless of routing-table
    // preference (the server's tunnel endpoint is *also* local on
    // this single-host setup; without -I the kernel would short-
    // circuit via `lo`). -c 1 sends one echo, -W 1 waits up to a
    // second for the reply, -n suppresses reverse DNS.
    //
    // The reply may or may not come back — depending on how the
    // host's routing table resolves the return path it might loop
    // through `lo`. We don't care: the assertion is about the
    // request reaching the *server* pppN, which is what M6g's
    // userspace forwarder must deliver.
    let server_endpoint = local_addr_of(ip_bin, server_ifname)
        .ok_or_else(|| format!("could not read local addr of `{server_ifname}`"))?;
    let ping_out = Command::new("ping")
        .args([
            "-c",
            "1",
            "-W",
            "1",
            "-n",
            "-I",
            &client_ifname,
            &server_endpoint.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn ping: {e}"))?;
    // Ignore ping exit status — see comment above.
    let _ = ping_out;

    // Give the kernel a moment to update interface stats after the
    // packet is delivered (the counter update happens in the
    // softirq path; nominally instantaneous, but a small grace
    // makes the test less flaky on a loaded box).
    std::thread::sleep(Duration::from_millis(200));

    let rx_after = read_rx_bytes(ip_bin, server_ifname)
        .ok_or_else(|| format!("could not re-read rx_bytes on `{server_ifname}`"))?;
    let tx_after = read_tx_bytes(ip_bin, server_ifname)
        .ok_or_else(|| format!("could not re-read tx_bytes on `{server_ifname}`"))?;

    Ok(TrafficObservation {
        server_rx_before: rx_before,
        server_rx_after: rx_after,
        server_tx_before: tx_before,
        server_tx_after: tx_after,
        client_ifname,
    })
}

/// Walk `ip -j addr show` and return the name of any interface
/// carrying `target` as one of its local IPv4 addresses. Returns the
/// first match (most setups only ever have one).
fn find_ifname_with_local_addr(ip_bin: &std::path::Path, target: Ipv4Addr) -> Option<String> {
    let out = Command::new(ip_bin)
        .args(["-o", "-4", "addr", "show"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let txt = String::from_utf8_lossy(&out.stdout);
    let needle = format!(" inet {target}");
    for line in txt.lines() {
        if line.contains(&needle) {
            // `ip -o addr show` lines look like:
            //   "21: ppp2    inet 10.99.0.42 peer 10.255.255.1/32 ..."
            // Grab field 1 (after the leading "N: ").
            let after_idx = line.find(": ").map(|i| i + 2)?;
            let rest = &line[after_idx..];
            let name = rest.split_ascii_whitespace().next()?.to_string();
            return Some(name);
        }
    }
    None
}

/// Return the local IPv4 address of `ifname` as reported by
/// `ip -o -4 addr show dev <ifname>`. Returns `None` on parse
/// failure or no address.
fn local_addr_of(ip_bin: &std::path::Path, ifname: &str) -> Option<Ipv4Addr> {
    let out = Command::new(ip_bin)
        .args(["-o", "-4", "addr", "show", "dev", ifname])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let txt = String::from_utf8_lossy(&out.stdout);
    let mut tokens = txt.split_ascii_whitespace();
    while let Some(t) = tokens.next() {
        if t == "inet" {
            let addr_with_mask = tokens.next()?;
            let addr = addr_with_mask.split('/').next()?;
            return addr.parse().ok();
        }
    }
    None
}

/// Read `rx_bytes` from `ip -s link show dev <ifname>`. The `-s`
/// output is space-separated and the rx-byte counter is the first
/// integer on the line immediately following "RX: bytes packets ...".
fn read_rx_bytes(ip_bin: &std::path::Path, ifname: &str) -> Option<u64> {
    read_link_counter(ip_bin, ifname, "RX:")
}

/// Read `tx_bytes` from `ip -s link show dev <ifname>`. Symmetric
/// counterpart to [`read_rx_bytes`].
fn read_tx_bytes(ip_bin: &std::path::Path, ifname: &str) -> Option<u64> {
    read_link_counter(ip_bin, ifname, "TX:")
}

fn read_link_counter(ip_bin: &std::path::Path, ifname: &str, section: &str) -> Option<u64> {
    let out = Command::new(ip_bin)
        .args(["-s", "link", "show", "dev", ifname])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let txt = String::from_utf8_lossy(&out.stdout);
    let mut lines = txt.lines();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with(section) {
            let values = lines.next()?;
            return values.split_ascii_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Extract `key=value` (text format) or `"key":"value"` (JSON
/// format) from a tracing log line. Returns the value or `None` if
/// absent. Used by the e2e test to pluck `ifname=ppp0` (or
/// `"ifname":"ppp0"`) out of the "kernel PPP unit attached" line.
fn extract_kv(line: &str, key: &str) -> Option<String> {
    // JSON-style: "key":"value"
    let json_needle = format!("\"{key}\":\"");
    if let Some(start) = line.find(&json_needle) {
        let rest = &line[start + json_needle.len()..];
        let end = rest.find('"').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    // Text-style: key=value
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
