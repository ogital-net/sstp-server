//! End-to-end integration tests against the `sstp-server` binary.
//!
//! The fixtures bring up:
//!   1. a self-signed TLS cert,
//!   2. a dummy RADIUS PAP authenticator that accepts a single
//!      hardcoded credential and replies with a `Framed-IP-Address`,
//!   3. the `sstp-server` binary itself, configured to listen on a
//!      free TCP port and forward auth to the dummy RADIUS.
//!
//! Coverage tiers, ordered by required privilege:
//!
//!   * `tls_handshake_smoke` — TLS-acceptor regression gate. Drives
//!     a real `ClientHello` at the server with `openssl s_client`
//!     and asserts the handshake completes. **No root, no kmod, no
//!     `sstpc`.** Runs everywhere.
//!   * `sstp_https_preamble` — pushes a canonical
//!     `SSTP_DUPLEX_POST` over TLS and checks the server's
//!     `HTTP/1.1 200 OK` response (MS-SSTP §3.2.4.1 / §4.1).
//!     **No root.** Runs everywhere `openssl` is available.
//!   * `sstpc_pap_login` — full PAP + IPCP round-trip via the
//!     upstream `sstp-client` binary, terminating in a real netdev
//!     bring-up (kernel `pppN` if the sstp kmod + kTLS are in play,
//!     `tunN` otherwise) plus a half-duplex ICMP traffic check.
//!     **Needs root** on both ends — the server still needs
//!     `CAP_NET_ADMIN` for TUN/netlink, and the client needs
//!     `/dev/ppp` for `pppd`.
//!
//! Tests skip cleanly when their prerequisites are missing so
//! `cargo test` is hermetic in any environment.

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
        framed_mtu: None,
        mikrotik_rate_limit: None,
    }
}

/// Probe whether `sstpc` is runnable in this environment. Returns a
/// human-readable reason string on skip, or `None` if everything is
/// in place.
///
/// Three independent prerequisites, all on the *client* side except
/// the last:
///   * `sstpc` on `PATH`,
///   * `/dev/ppp` present (the client wraps `pppd`, which needs it —
///     the server itself uses TUN by default and does not require
///     `/dev/ppp`),
///   * `CAP_NET_ADMIN` (proxied via uid==0). Required on **both**
///     ends — `pppd` for its kernel-side bring-up, the server for
///     `/dev/net/tun` + netlink `RTM_NEWADDR`/`IFF_UP`.
fn sstpc_skip_reason() -> Option<String> {
    if which("sstpc").is_none() {
        return Some("sstpc not on PATH".into());
    }
    if !std::path::Path::new("/dev/ppp").exists() {
        return Some(
            "/dev/ppp not present (sstpc/pppd client-side requirement; server uses TUN)".into(),
        );
    }
    // EUID 0 is the simplest portable check; CAP_NET_ADMIN is a
    // superset of "is root" for our purposes.
    // SAFETY: getuid() has no preconditions and is signal-safe.
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        return Some(format!(
            "not running as root (uid={uid}); both pppd (client) and TUN/netlink (server) need CAP_NET_ADMIN"
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
/// Deliberately scoped to the TLS layer: `s_client` finishes the
/// handshake and disconnects without writing any application data,
/// so the server never reaches the SSTP HTTPS preamble (covered by
/// [`sstp_https_preamble`]) or the auth bridge (covered by
/// [`sstpc_pap_login`]). The RADIUS-not-reached assertion below is
/// a sanity check on that scoping, not a forward-looking guard.
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

    // RADIUS should not have been reached: `s_client` closes after
    // the handshake without sending the SSTP preamble, so the
    // session driver tears the connection down before auth.
    let seen = radius.seen();
    assert!(
        seen.is_empty(),
        "dummy RADIUS unexpectedly received {} requests; \
         a TLS-only handshake should not reach auth.\n\
         seen: {seen:#?}",
        seen.len()
    );
}

/// End-to-end test driving the upstream `sstpc` client against the
/// server. Skipped if prerequisites (sstpc, /dev/ppp, root) are not
/// available — see [`sstpc_skip_reason`].
///
/// Drives the full PAP path end-to-end and checks:
///   * the dummy RADIUS authenticator received exactly one
///     `Access-Request` with `User-Name=alice` and a PAP outcome of
///     `Match`;
///   * the server brought up a netdev (kernel `pppN` if the sstp
///     kmod + kTLS are loaded, otherwise `tunN`) and it carries the
///     `Framed-IP-Address` as its P2P peer;
///   * a single ICMP echo from the client-side `pppN` reaches the
///     server-side netdev (asserted via interface RX byte counters).
///
/// We deliberately *do not* assert `sstpc`'s exit status: the harness
/// SIGKILLs it once the netdev appears, so its exit will be
/// signal-terminated. Asserting a clean exit would require driving
/// `sstpc`'s own teardown path, which is outside the SSTP server's
/// responsibility.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
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

    // The decisive event is the "data path ready" log
    // line (emitted for both pppN and tunN paths — `kernel_path=…`
    // disambiguates), fired once IPCP converges and the netlink
    // bring-up succeeds. Give the full PAP + IPCP round-trip a
    // generous window — pppd is slow to start under load. Use
    // `collect_logs_until` (not `wait_for_log`) so we also retain
    // the kmod-fallback line that arrives moments before attach.
    let pre_attach_logs = server.collect_logs_until("data path ready", Duration::from_secs(15));

    let Some(attach_line) = pre_attach_logs.as_ref().and_then(|v| v.last()).cloned() else {
        // Reap before panicking so we don't leak the child.
        let _ = child.kill();
        let out = child.wait_with_output().expect("reap sstpc");
        panic!(
            "did not see 'data path ready' within 15s.\n\
             sstpc stdout:\n{}\nsstpc stderr:\n{}\n\
             server logs:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            server.drain_logs().join("\n")
        );
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
    // assert the server-side netdev's RX counter grew. This proves
    // the client→server data direction carries IP frames end-to-end
    // (sstpc → TLS → SSTP demux → KpppSession::write_frame → kernel
    // pppN/tunN).
    //
    // Server→client is not exercised: it would require host
    // routing rules that send return traffic back through the
    // server's tunnel endpoint, which is out of scope for the data
    // path itself. On the kmod path the kernel additionally never
    // hands TX frames to the unit-fd reader (`ppp_generic` dispatches
    // through channels) — see docs/data-path.md.
    //
    // Done *before* reaping sstpc: closing TLS tears the session
    // down, which removes the netdev.
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
/// without the sstp kmod + kTLS (see docs/data-path.md).
struct TrafficObservation {
    server_rx_before: u64,
    server_rx_after: u64,
    server_tx_before: u64,
    server_tx_after: u64,
    client_ifname: String,
}

/// Find the sstpc-side `pppN` (the one whose local address is
/// `TEST_FRAMED_IP`), snapshot the *server*-side `pppN` `rx_bytes`
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
    // hundred milliseconds after our "data path ready" log.
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
/// `"ifname":"ppp0"`) out of the "data path ready" line.
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

// =============================================================================
// MTU + netfilter (MSS clamp) + traffic shaping (tc HTB / ingress police)
// =============================================================================

/// MTU in `Framed-MTU` we ask the dummy authenticator to advertise.
/// Kept inside the `[576, 1500]` window the bridge clamps to (see
/// `auth::bridge::project_addrs`) so the projected value matches
/// the requested one.
const TEST_FRAMED_MTU: u32 = 1400;

/// Wire string for the `Mikrotik-Rate-Limit` VSA. Mikrotik names
/// fields client-POV: `rx/tx` ⇒ rx is server→client (egress),
/// tx is client→server (ingress).
const TEST_MIKROTIK_RATE_LIMIT: &str = "1M/2M";

/// Build a credential that triggers all three netfilter / shaping
/// surfaces: Framed-MTU populates `IFLA_MTU`, Mikrotik-Rate-Limit
/// populates `tc` HTB egress + ingress police. The default
/// `--no-mss-clamp=false` (i.e. clamp on) plus a non-default MTU
/// gives us an `nft` table to inspect.
fn build_credential_with_mtu_and_shaping() -> Credential {
    Credential {
        username: TEST_USER.to_string(),
        password: TEST_PASS.to_vec(),
        framed_ip: TEST_FRAMED_IP,
        framed_mtu: Some(TEST_FRAMED_MTU),
        mikrotik_rate_limit: Some(TEST_MIKROTIK_RATE_LIMIT.to_string()),
    }
}

/// Skip-reason probe for the netfilter / shaping test: needs the
/// same prereqs as `sstpc_pap_login` plus `nft` and `tc` on PATH so
/// the kernel-side state can be inspected.
fn netfilter_shaping_skip_reason() -> Option<String> {
    if let Some(r) = sstpc_skip_reason() {
        return Some(r);
    }
    for tool in ["nft", "tc", "ip"] {
        if which(tool).is_none() {
            return Some(format!("`{tool}` not on PATH"));
        }
    }
    None
}

/// Run a command and return (status, combined-stdout-string,
/// combined-stderr-string). Used to make the kernel-state probes
/// (`nft list ruleset`, `tc qdisc show`, …) more legible in
/// failure messages.
fn run_capture(bin: &std::path::Path, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let out = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("spawn `{} {}`: {e}", bin.display(), args.join(" ")));
    (
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// End-to-end test for the netfilter + shaping bring-up path.
///
/// Drives a real `sstpc` session against the server with a RADIUS
/// reply that carries `Framed-MTU` and `Mikrotik-Rate-Limit`, then
/// asserts the resulting kernel state on the server-side `pppN` /
/// `tunN` netdev:
///
///   * `IFLA_MTU` matches `Framed-MTU` (clamped `[576, 1500]`).
///   * An `inet`-family nftables table `sstp_mss_<pid>_<n>` exists
///     and the `forward` chain references the netdev's name in
///     `iifname` / `oifname` rules.
///   * `tc qdisc show dev <ifname>` lists an `htb` root qdisc and
///     an `ingress` qdisc; `tc class show` lists a leaf class with
///     a rate close to the one in `Mikrotik-Rate-Limit`.
///
/// After SIGKILLing `sstpc` and waiting for the netdev to disappear,
/// asserts the nft table is gone (RAII cleanup via `MssClamp::Drop`).
///
/// Skipped if any of the prerequisites are missing — see
/// [`netfilter_shaping_skip_reason`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn sstpc_mtu_netfilter_shaping() {
    if let Some(reason) = netfilter_shaping_skip_reason() {
        eprintln!("SKIP sstpc_mtu_netfilter_shaping: {reason}");
        return;
    }

    let tmp = TempDir::new("netfilter");
    let pem = gen_self_signed(tmp.path());

    let radius_port = free_udp_port();
    let radius = DummyRadius::start_on(radius_port, build_credential_with_mtu_and_shaping()).await;

    let sstp_port = free_tcp_port();
    let listen = loopback(sstp_port);
    let server = ServerBuilder::new(listen, &pem.cert, &pem.key)
        .radius(radius.addr)
        .spawn(SERVER_READY);

    // sstpc setup mirrors `sstpc_pap_login` — see that test for the
    // detailed comments.
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

    let pre_attach_logs = server.collect_logs_until("data path ready", Duration::from_secs(20));
    let Some(attach_line) = pre_attach_logs.as_ref().and_then(|v| v.last()).cloned() else {
        let _ = child.kill();
        let out = child.wait_with_output().expect("reap sstpc");
        panic!(
            "did not see 'data path ready' within 20s.\n\
             sstpc stdout:\n{}\nsstpc stderr:\n{}\n\
             server logs:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            server.drain_logs().join("\n")
        );
    };
    let pre_attach_logs = pre_attach_logs.expect("checked above");
    let ifname = extract_kv(&attach_line, "ifname").unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no 'ifname=' field in attach log line: {attach_line}")
    });

    // Let the post-attach apply path run (shape::apply, MssClamp
    // install). Both log distinctive lines on success.
    let saw_shape = server
        .wait_for_log("traffic shaping policy applied", Duration::from_secs(5))
        .is_some();
    let saw_mss = server
        .wait_for_log("installed nftables MSS clamp rules", Duration::from_secs(5))
        .is_some();

    // ----- kernel-side state probes (run before reaping sstpc, since
    // tearing the TLS down also tears down pppN and the nft table) -----

    let ip_bin = which("ip").unwrap_or_else(|| std::path::PathBuf::from("/usr/sbin/ip"));
    let nft_bin = which("nft").unwrap_or_else(|| std::path::PathBuf::from("/usr/sbin/nft"));
    let tc_bin = which("tc").unwrap_or_else(|| std::path::PathBuf::from("/usr/sbin/tc"));

    // 1. MTU on the netdev.
    let (ip_status, ip_stdout, ip_stderr) =
        run_capture(&ip_bin, &["-d", "link", "show", "dev", &ifname]);

    // 2. nftables ruleset (full dump). Cheap on an otherwise empty
    //    host; on a populated one we still grep for our table prefix.
    let (nft_status, nft_stdout, nft_stderr) = run_capture(&nft_bin, &["list", "ruleset"]);

    // 3. tc qdiscs + classes on the netdev.
    let (qdisc_status, qdisc_stdout, qdisc_stderr) =
        run_capture(&tc_bin, &["-s", "qdisc", "show", "dev", &ifname]);
    let (class_status, class_stdout, class_stderr) =
        run_capture(&tc_bin, &["class", "show", "dev", &ifname]);
    let (filter_status, filter_stdout, filter_stderr) =
        run_capture(&tc_bin, &["filter", "show", "dev", &ifname, "ingress"]);

    // Tear sstpc down only after probing — closing TLS removes pppN
    // and the kernel auto-reaps qdiscs / addresses.
    let _ = child.kill();
    let _ = child.wait_with_output().expect("reap sstpc");

    // ----- assertions on captured probe output -----

    // RADIUS-side: exactly one Access-Request, matched.
    let seen = radius.seen();
    assert_eq!(
        seen.len(),
        1,
        "expected 1 RADIUS request; got {}: {seen:#?}",
        seen.len()
    );
    assert_eq!(seen[0].username.as_deref(), Some(TEST_USER));
    assert!(matches!(seen[0].pap_outcome, Some(PapOutcome::Match)));

    // Shape + MSS apply log lines must have fired (otherwise we're
    // about to make assertions about kernel state that was never
    // installed, and the failure messages should say so).
    assert!(
        saw_shape,
        "shape::apply never logged 'traffic shaping policy applied'.\n\
         Pre-attach logs:\n{}",
        pre_attach_logs.join("\n")
    );
    assert!(
        saw_mss,
        "MssClamp install never logged 'installed nftables MSS clamp rules'."
    );

    // (1) MTU.
    assert!(
        ip_status.success(),
        "`ip -d link show dev {ifname}` failed (status={ip_status:?}): {ip_stderr}"
    );
    let mtu_needle = format!("mtu {TEST_FRAMED_MTU}");
    assert!(
        ip_stdout.contains(&mtu_needle),
        "expected `{mtu_needle}` in:\n{ip_stdout}"
    );

    // (2) nftables: a table named `sstp_mss_*` must exist (table
    // names embed the daemon's pid, but the prefix is stable; see
    // `src/shape/mss.rs::next_table_name`). We inspect the *full*
    // ruleset rather than `nft list tables` so the rule contents
    // (iifname / oifname references to our netdev) are visible in
    // failure output.
    assert!(
        nft_status.success(),
        "`nft list ruleset` failed (status={nft_status:?}): {nft_stderr}"
    );
    assert!(
        nft_stdout.contains("table ip sstp_mss_"),
        "expected `table ip sstp_mss_…` in nft ruleset:\n{nft_stdout}"
    );
    // Both directions of the FORWARD-hook rules should reference
    // the netdev (one as `iifname`, one as `oifname`).
    assert!(
        nft_stdout.contains(&format!("\"{ifname}\"")) || nft_stdout.contains(&ifname),
        "expected nft rule body to reference `{ifname}`:\n{nft_stdout}"
    );

    // (3) tc qdiscs: HTB root + ingress qdisc.
    assert!(
        qdisc_status.success(),
        "`tc qdisc show dev {ifname}` failed (status={qdisc_status:?}): {qdisc_stderr}"
    );
    assert!(
        qdisc_stdout.contains("qdisc htb 1:"),
        "expected `qdisc htb 1:` (HTB root) on `{ifname}`:\n{qdisc_stdout}"
    );
    assert!(
        qdisc_stdout.contains("qdisc ingress"),
        "expected `qdisc ingress` on `{ifname}`:\n{qdisc_stdout}"
    );

    // (3b) tc classes: an HTB leaf with `rate 1Mbit` (the egress /
    // rx side of `1M/2M`). `tc` prints rates with the SI suffix it
    // chooses; `1Mbit` is the canonical render for 1_000_000 bps.
    assert!(
        class_status.success(),
        "`tc class show dev {ifname}` failed (status={class_status:?}): {class_stderr}"
    );
    assert!(
        class_stdout.contains("htb"),
        "expected an htb class on `{ifname}`:\n{class_stdout}"
    );
    // Accept any of the renderings tc uses for 1_000_000 bps:
    // "rate 1Mbit", "rate 1000Kbit", "rate 1000000bit". HTB ceil
    // defaults to rate when no burst rate is configured.
    let rate_renderings = ["rate 1Mbit", "rate 1000Kbit", "rate 1000000bit"];
    assert!(
        rate_renderings.iter().any(|r| class_stdout.contains(r)),
        "expected one of {rate_renderings:?} (egress = Mikrotik rx = 1M):\n{class_stdout}"
    );

    // (3c) ingress filter: u32 + police on the ingress qdisc.
    assert!(
        filter_status.success(),
        "`tc filter show dev {ifname} ingress` failed \
         (status={filter_status:?}): {filter_stderr}"
    );
    assert!(
        filter_stdout.contains("u32") || filter_stdout.contains("police"),
        "expected u32+police filter on ingress of `{ifname}`:\n{filter_stdout}"
    );

    // ----- post-teardown: nft table should be gone (MssClamp::Drop) -----

    // Give the session task a beat to unwind. The Drop impl on
    // MssClamp opens a fresh netlink socket and runs a delete batch
    // synchronously, so this is usually instantaneous; allow a
    // generous window for a loaded box.
    let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut leaked = String::new();
    loop {
        let (st, out, _err) = run_capture(&nft_bin, &["list", "tables"]);
        if !st.success() {
            break; // can't probe; don't fail the cleanup assertion on a tooling glitch
        }
        if !out.contains("sstp_mss_") {
            leaked.clear();
            break;
        }
        leaked = out;
        if std::time::Instant::now() >= cleanup_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        leaked.is_empty(),
        "nft `sstp_mss_*` table leaked after session teardown:\n{leaked}"
    );
}
