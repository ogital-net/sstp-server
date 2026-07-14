# Roadmap

This document tracks work needed to bring `sstp-server` to feature
parity with mature open-source PPP/VPN concentrators. Items are
grouped by theme; within each theme they are ordered roughly by
dependency / impact. Tick boxes reflect the state of the v0.1
codebase.

The deliberate non-goals from [CLAUDE.md](CLAUDE.md) still stand:
no Windows/macOS port, no general-purpose PPP library, no auth
backend other than RADIUS, no in-tree config file parser. Anything
incompatible with those constraints belongs in a separate project.

---

## 1. Protocol completeness

### IPv6

- [ ] **IPV6CP** ([RFC 5072](https://www.rfc-editor.org/rfc/rfc5072)).
      The in-process PPP plane currently negotiates IPCP only. Adds
      a sibling FSM next to [`ppp::ipcp`](src/ppp/ipcp.rs) that
      negotiates `Interface-Identifier` (option 1) and, optionally,
      `IPv6-Compression-Protocol` (option 2, almost always rejected).
- [ ] **RADIUS IPv6 attributes**: consume `Framed-IPv6-Prefix`,
      `Framed-Interface-Id`, `Delegated-IPv6-Prefix`, and the
      `DNS-Server-IPv6-Address` VSAs from the Access-Accept; surface
      them through `auth::reply::AuthAccept` alongside the existing
      v4 fields.
- [ ] **Netlink v6 bring-up**: extend [`kppp::netlink`](src/kppp/netlink.rs)
      to add `RTM_NEWADDR` for `AF_INET6` on `pppN`, install an
      on-link `/64` (or PD route) and the unicast LL address.
- [ ] **kmod v6**: confirm the in-tree kmod's `ppp_input` path
      passes `ETH_P_IPV6` payloads through unchanged (it should —
      `ppp_generic` does the protocol demux — but we have no e2e
      coverage yet).
- [ ] **Sticky v6 assignment**: same hash-bucket lookup as v4 when
      the RADIUS pool returns a fresh prefix per session.

### PPP

- [ ] **LCP echo-based idle detection**: send `Echo-Request` every
      `--lcp-echo-interval` seconds, drop after `--lcp-echo-failure`
      consecutive misses. The state machine in [`ppp::lcp`](src/ppp/lcp.rs)
      handles the messages; the periodic driver does not exist yet.
- [x] **`Session-Timeout` / `Idle-Timeout` enforcement** (RFC 2865
      §5.27–5.28). *(done)* Both are consumed from the
      Access-Accept via `auth::reply::SessionPolicy` and installed
      in `drive_sstp` as one-shot `tokio::time::Sleep` deadlines.
      `Idle-Timeout` is re-armed whenever the accounting interim
      detects octet-counter movement.
- [ ] **Honour peer-advertised LCP MRU on netdev MTU**: today
      we accept the peer's `MRU` option in their Configure-Request
      but don't propagate the value to the `pppN` / `tun0` MTU.
      The default (1400) and RADIUS `Framed-MTU` already feed the
      netdev correctly; the missing piece is taking the *minimum*
      of (default, `Framed-MTU`, peer MRU). In practice all real
      clients (Windows, Mikrotik, sstpc) advertise 1500 so this
      never bites — defer until a deployment hits it.
- [x] **PFC / ACFC option handling** *(done)*: the receive path
      already accepts both compressed forms — `decode_frame` in
      [src/ppp/frame.rs](src/ppp/frame.rs) strips an optional
      `0xFF 0x03` prefix and detects 1-byte vs 2-byte Protocol
      fields via [RFC 1661] §2 parity; the LCP classifier in
      [src/ppp/driver.rs](src/ppp/driver.rs) Acks peer-requested
      `ProtocolFieldCompression` (7) / `AddressControlFieldCompression`
      (8) options. Unit-tested by `decode_acfc_only` /
      `decode_pfc_compressed` / `decode_acfc_and_pfc` in `frame.rs`
      and `ack_acceptable_lcp_cr` in `driver.rs`. Outbound
      compression (requesting the options in our own CR) is a
      separate enhancement and intentionally out of scope.
- [x] **Reject MPPC / MPPE Configure-Requests politely** *(done)*:
      `Ppp::on_frame` now emits an LCP `Protocol-Reject`
      ([RFC 1661] §5.7) for any inbound frame whose protocol we
      don't speak — covering CCP (0x80FD, the MPPC/MPPE carrier),
      ECP (0x8053), Multilink, CBCP, etc. Identifier is bumped
      per packet via `Ppp::lcp_extra_id_counter` as the RFC
      requires; body is `Rejected-Protocol(2B) || Rejected-
      Information` truncated to 1500 − LCP header − 2 bytes.
      Frames received before LCP reaches Opened are still
      silently discarded per the same RFC clause. Verified by
      `ccp_configure_request_after_lcp_open_gets_protocol_reject`,
      `unknown_protocol_before_lcp_opens_is_silently_dropped`,
      and `protocol_reject_identifier_changes_per_packet` in
      [src/ppp/driver.rs](src/ppp/driver.rs).

### SSTP control plane

- [ ] **Server-initiated `Call-Disconnect` with reason codes** for
      the operator-driven teardown paths (`disable session`,
      shutdown, CoA-Disconnect). The framing exists; the dispatcher
      currently just drops the TLS socket.
- [x] **`Echo-Request`/`Echo-Response` keepalive timer** ([MS-SSTP]
      §3.2.5.2.4). *(done)* The per-worker periodic tick (1 s
      timerfd) sends `PeriodicTick` to all sessions; each session
      checks `last_rx` and sends an Echo Request after 60 s idle,
      aborts after 120 s with no response. Zero per-session timer
      overhead — no timer-wheel entries or timerfd per session.
- [ ] **TLS 1.3 `KeyUpdate` handling on the kmod path**: the kmod
      already surfaces `SSTP_EVT_TLS_REKEY_NEEDED`; today's userspace
      handler tears the session down cleanly (no Stop loss, metric
      `sstp_session_teardown_keyupdate`, client auto-reconnects).
      Server-originated post-handshake records are ruled out at
      ctx-init time (`SSL_CTX_set_num_tickets(0)` +
      `SSL_OP_NO_TICKET`), so the only path to this teardown is a
      *client*-initiated `KeyUpdate`, which Windows clients do not
      send in practice. Full re-keying needs a kmod ABI extension
      to surface the `KeyUpdate` body to userspace, plus an
      HKDF-driven `setsockopt(SOL_TLS, TLS_RX, …)` re-install (and
      `TLS_TX` if the peer set `request_update`). v0.2 work.

---

## 2. RADIUS

- [ ] **CoA / Disconnect dispatch**: the listener, parser and
      response packing are landed in [`auth::coa`](src/auth/coa.rs),
      but the `Handler` trait has no implementation that talks to
      the session `Registry`. Wire it through the same MPSC channel
      `Registry::broadcast_disconnect` uses today.
- [ ] **CoA-driven re-shape**: on `CoA-Request` carrying a fresh
      `Mikrotik-Rate-Limit` (or `Filter-Id`), reinstall HTB on the
      live unit with `NLM_F_REPLACE`. Plumbing in
      [`shape::Shaper`](src/shape/mod.rs) supports it; the session
      task does not yet listen for it.
- [x] **`Acct-Interim-Interval` honour** *(done)*: the period from
      the Access-Accept overrides the default 60 s cadence.
      Driven by the per-worker periodic tick — each session
      checks `last_acct_interim.elapsed()` locally, with jitter
      (session ID mod period) to spread interims evenly across
      the interval and avoid thundering-herd bursts on the
      RADIUS server.
- [ ] **`Filter-Id` → nftables**: install a per-session nft chain
      under `inet sstp filter-<id>` and bind it to the `pppN`
      ingress hook. Symmetric design to `shape::`: hand-rolled
      netlink (nfnetlink) so the daemon doesn't fork+exec `nft`.
- [ ] **`Acct-Multi-Session-Id`** for multi-link bundles. Not
      meaningful today (SSTP is single-link), but cheap to populate
      from the same UUID that backs `Session::id`.
- [ ] **EAP retransmit / fragmentation soak**: the pass-through
      handles fragmentation, but we have no integration test that
      drives PEAP / EAP-TLS through a real authenticator. Add one
      to [`tests/e2e.rs`](tests/e2e.rs) gated on `freeradius` being
      on `PATH`.
- [ ] **Username transformation**: optional `--strip-realm` /
      `--rewrite-username <regex>` for deployments that need to
      normalise `DOMAIN\user`, `user@realm` etc. before the
      Access-Request. Trivial wrapper around the existing
      `submit_pap` / `submit_mschapv2` calls.
- [ ] **Per-realm RADIUS routing**: a `--realm-route <pattern>:<host:port>`
      flag, so a single NAS can fan auth out across tenants. Either
      this lands or operators front the daemon with a RADIUS proxy
      (FreeRADIUS, radsecproxy) — document the latter as the
      default answer.

---

## 3. IP assignment & address management

The current design is **RADIUS-only** assignment with no in-process
pool. That is deliberate and stays. Things still missing:

- [ ] **Sticky per-username v4 binding** in the RADIUS server's
      pool is the operator's responsibility, but we should
      surface the resolved `Framed-IP-Address` in `show sess` so
      operators can see what happened without grepping logs.
- [ ] **Duplicate-IP rejection**: if RADIUS hands out an address
      already in use by another live session on this NAS, reject
      the new session with a logged warning instead of letting the
      kernel netlink call fail mid-bring-up. Cheap: a
      `HashSet<Ipv4Addr>` keyed by the registry.
- [ ] **`Framed-Pool` attribute** (RFC 2869 §5.6) is intentionally
      unsupported — the pool lives in RADIUS. Document this in
      [docs/admin-guide.md](docs/admin-guide.md) so operators know.

---

## 4. TLS

- [ ] **SNI dispatch**: today there is one `SSL_CTX` for the
      process. Allow `--cert NAME:cert.pem --key NAME:key.pem`
      repeated, install a `SSL_CTX_set_client_hello_cb` selector,
      and pick the cert per ClientHello. Lets a single daemon serve
      multiple FQDNs (Windows accepts whatever SAN matches the URL
      the user typed).
- [ ] **Cipher allowlist flag**: `--tls-ciphers <openssl-string>`
      with a sane default that matches the kTLS-eligible set
      (AES-GCM, ChaCha20-Poly1305). Without this, an operator who
      needs FIPS-only ciphers has to rebuild.
- [ ] **TLS 1.3 only flag**: `--tls-min-version 1.3` (default
      stays `1.2` for Windows ≤ 1909 compatibility).
- [ ] **Client-certificate authentication**: optional second
      factor before PPP auth runs. RADIUS gets a
      `User-Name = <subject CN>` Access-Request for accounting /
      authorization. Opt-in via `--require-client-cert <ca.pem>`.
- [ ] **OCSP stapling**: `--ocsp-responder <url>` with an
      in-process fetch + cache. SoftEther / accel-ppp both lack
      this; doing it well would be a differentiator.
- [x] **ALPN advertisement** *(done)*: a no-op for SSTP itself,
      but Windows / some `sstpc` builds send `http/1.1` in their
      ClientHello, and certain load-balancers / IDS appliances
      drop sessions when the server fails to echo back a value
      the client offered. `SslContext::server_from_pem` now
      installs an `SSL_CTX_set_alpn_select_cb` that selects
      `http/1.1` if the peer offered it (via
      `SSL_select_next_proto` against a static wire-format
      buffer) and returns `SSL_TLSEXT_ERR_NOACK` otherwise — same
      wire result as not configuring ALPN at all when the client
      sent no extension. See [src/crypto/tls.rs](src/crypto/tls.rs).

---

## 5. Data path performance

The kmod fast path is the headline; the remaining work is making
sure we exploit it everywhere.

- [ ] **GSO/GRO on `pppN`** (kmod path). TX-side GSO should
      already be on for free: mainline `ppp_generic` advertises
      `NETIF_F_GSO_SOFTWARE`, so the kernel software-segments
      super-skbs before they reach our `start_xmit`. Confirm with
      `ethtool -k pppN`. RX-side GRO is a real kmod change —
      switch the demux path from `netif_rx` to `napi_gro_receive`
      against a NAPI struct registered per channel, plus a kmod
      ABI bump. Separate work item; benchmark first to see if
      it's worth it given the kmod path is already kTLS-zero-copy
      end-to-end.
- [x] **IPv6 MSS clamp** *(v4 done, v6 deferred)*: the per-session
      MSS clamp has been replaced with a shared nftables table —
      one table per process, one chain per distinct MSS value, and
      named sets for O(1) per-packet interface lookup. Replaces
      the previous per-session table approach (565 tables × 2
      rules → 1 table × 2 set-lookup chains). `NFTA_SET_USERDATA`
      emits only the 6-byte `KEYBYTEORDER` blob for nft 1.0.6
      compatibility. The `NFPROTO_IPV6` sibling table will land
      alongside §1's IPV6CP work.
- [ ] **Per-CPU listener accounting**: `SO_INCOMING_CPU` /
      `SO_REUSEPORT_CBPF` to pin sessions to the NUMA-local
      worker. Today the kernel hashes by 4-tuple, which is
      cache-friendly enough but not optimal on multi-socket boxes.
      Realistic value is anti-DoS hardening for reconnection
      storms (one extra cache-friendly accept per SYN), not a
      steady-state win — once the kmod path takes over, packet
      handling runs in softirq and is unaffected by accept-side
      placement. SSTP's connect rate is low enough that this
      barely registers under normal load.

      Inside a VM the gain is usually negligible: vCPUs aren't
      pinned to physical cores by default (host scheduler is free
      to migrate them across L3 domains and NUMA nodes), virtio-
      net steering happens on the host side of the boundary, and
      cloud VM shapes ≤ 64 vCPU usually present a single guest
      NUMA node. The optimisation is only worth turning on for
      bare-metal hosts, dedicated/pinned instances (`*.metal`,
      sole-tenant + NUMA pinning), and SR-IOV / DPDK-style
      placement.

      Implementation should make this an **auto-off-in-VM**
      default. Detect virtualisation at startup and skip the
      `SO_REUSEPORT_CBPF` install (still keep the per-worker
      reuseport sockets, that's worthwhile everywhere). Cheap
      detection vectors:

      - **CPUID hypervisor bit** on x86_64 (`leaf 1 / ECX bit 31`,
        the `hypervisor` flag in `/proc/cpuinfo`) — set by every
        sane hypervisor (VMware, Hyper-V, KVM, Xen HVM, EC2
        Nitro, GCE).
      - **DMI vendor**: `/sys/class/dmi/id/sys_vendor` reports
        `VMware, Inc.` / `QEMU` / `Microsoft Corporation`
        (Hyper-V) / `Amazon EC2` / `Google` / `OpenStack
        Foundation` / `innotek GmbH` (VirtualBox).
      - **aarch64**: same DMI path on UEFI-booted boards;
        `/sys/firmware/devicetree/base/hypervisor/compatible`
        on DT systems (`xen,xen`, `linux,kvm`).
      - **Containers vs bare-metal**: `/proc/1/cgroup` containing
        `docker` / `containerd` / `kubepods`, or
        `/.dockerenv` / `/run/.containerenv` existing. A
        container on a bare-metal host *should* still get the
        optimisation; only nested-virt containers should opt out.

      Override flag: `--cpu-pinning {auto,on,off}` (default
      `auto` = on for bare metal, off for VMs). Operators with
      pinned VMs flip it to `on` explicitly. Log the chosen mode
      and the detected environment at info on startup so
      misconfiguration is visible.
- [ ] **TUN fallback: GSO via `IFF_VNET_HDR` + batched
      `SSL_write`** (Mikrotik path). RouterOS' SSTP client only
      offers AES-CBC-SHA, which is not kTLS-eligible, so Mikrotik
      deployments always run on the TUN backend. Real 2–4× TX win
      from collapsing the per-segment work: kernel emits one
      super-skb up to 64 KiB per `read`, vnet header carries the
      pre-computed TCP checksum, we segment in userspace into
      MTU-sized PPP frames packed into a single contiguous buffer,
      then issue **one** `SSL_write` so libssl's per-call
      entry-lock + `send()` syscall cost is paid once per
      super-packet instead of per segment. Risks: IPv4 DF/fragment
      flag handling, ICMP-too-big when peer MTU < ours, IPv6
      plumbing (gated on §1). Needs a soak test driving real
      TCP-heavy load through a Mikrotik client to validate.
      Note: `recvmmsg`/`sendmmsg` do not apply — TUN is a char
      device, not a socket.
- [ ] **eBPF observability**: ship a USDT / kprobe set that gives
      `bpftrace`-friendly hook points for per-session latency
      histograms without instrumenting the daemon.
- [ ] **XDP probe drop** at the listener: install an XDP program
      that drops obviously-bogus SYNs (wrong dest port, malformed
      TLS ClientHello length) before they hit the accept queue.
      Anti-DoS hardening, not a throughput change.

---

## 6. Session & operations

- [ ] **Concurrent-session limit per username**: configurable cap
      (default 1) enforced at session bring-up against the registry.
      RADIUS-side limits work but a NAS-side enforcement is faster
      and reproducible.
- [ ] **Connection rate limiting**: token-bucket on incoming TCP
      accepts, per source-IP. Mitigates auth-loop / scan storms.
      Lives in `net::listener`, fed by a `dashmap`-free
      single-thread map per worker.
- [ ] **`show sess` filter / sort**: extend the control socket
      grammar with `show sess by-user <pattern>` and `show sess
      by-ip <cidr>`. The cross-worker fan-out machinery already
      exists.
- [ ] **`reload` control command**: re-read the TLS cert/key on
      demand (today only `SIGHUP` does this). Useful for operators
      who don't want to send signals from automation.
- [ ] **Crash dump artefact**: install a small `signal-hook`
      `SIGSEGV` handler that writes the per-session registry + the
      last 1k metric values to `/var/crash/sstp-server.<pid>` before
      re-raising. Optional: gate behind `--crash-dump-dir`.
- [ ] **Hot-restart with FD passing**: a long-poll item. `execve`
      the new binary, pass the listener FDs + the registry over a
      Unix socket. Lets operators upgrade without dropping active
      sessions. Significant engineering — only worth it if
      deployments actually ask.

---

## 7. Observability

- [ ] **Prometheus exporter sidecar** (out-of-tree): a 200-line
      Rust binary that reads the control socket and serves
      `/metrics` over HTTP. Lives in a separate crate so we don't
      pull `axum` / `hyper` into the daemon.
- [ ] **Structured per-session logs**: every log line in the
      session task should carry `session_id`, `user`, `peer_ip` as
      `tracing` fields. Most already do; audit and fill gaps.
- [ ] **Histogram support in the registry**: `sstp_auth_duration_seconds`
      and `sstp_session_duration_seconds` are declared in
      [CLAUDE.md](CLAUDE.md) but only implemented as counters
      today. A fixed-bucket HDR-style histogram, allocation-free
      on the record path, plus `show stat` rendering.
- [ ] **OpenTelemetry traces** (opt-in via cargo feature): one
      span per session covering accept → auth → bring-up →
      teardown. Useful when correlating with RADIUS-server traces.

---

## 8. Packaging & deployment

- [ ] **Container image** (`Dockerfile` + `ghcr.io/ogital-net/sstp-server`):
      the kmod is the awkward part. Two flavours: `kernel` (host
      kmod required, `--data-path kernel`) and `tun` (no kmod,
      runs in any container with `NET_ADMIN`).
- [ ] **Kubernetes manifest example**: DaemonSet + hostNetwork +
      `NET_ADMIN`, plus a sample NetworkPolicy. Lives under
      `examples/k8s/`, not in the deb.
- [x] **DKMS lifecycle on package install / kernel upgrade**
      *(done)*: the `sstp-server-dkms` package is wired through
      `dh-dkms` ([debian/rules](debian/rules) `override_dh_dkms`
      calls `dh_dkms -V $(KMOD_VERSION)`), so `dkms add` /
      `dkms build` / `dkms install` run from the helper-generated
      postinst — no hand-rolled `dkms install` in
      [debian/sstp-server.postinst](debian/sstp-server.postinst).
      `AUTOINSTALL="yes"` in [packaging/dkms.conf](packaging/dkms.conf)
      plus the stock `dkms` package's `/etc/kernel/header_postinst.d/dkms`
      hook handles automatic rebuilds on every kernel upgrade. The
      cert-renewal hook ([packaging/certbot-deploy-hook.sh](packaging/certbot-deploy-hook.sh))
      is unrelated — it sends `SIGHUP` to reload TLS material in
      place and intentionally does not touch DKMS.

      We deliberately do **not** set `BUILD_EXCLUSIVE_KERNEL`: the
      goal is the widest possible kernel support. Mainline
      `ppp_generic` + kTLS APIs the kmod uses have been stable
      since ~5.4, the module is verified on 6.8 and 6.12, and
      anything older that does compile cleanly is welcome to.
      Letting DKMS attempt the build and surface a real compiler
      error on truly unsupported kernels beats pre-judging via a
      regex.
- [ ] **DKMS install-path consolidation**: `dkms.conf` is currently
      installed twice during the deb build — once by
      [Makefile](Makefile) `install-kmod-src` (sed-substituting
      `@VERSION@`) and once by `dh_dkms` (templating
      `#MODULE_VERSION#` from
      [debian/sstp-server-dkms.dkms](debian/sstp-server-dkms.dkms)).
      They produce the same file today but the duplication is
      fragile. Pick one path; the `dh_dkms`-only flow is the
      idiomatic choice on the deb side, with `install-kmod-src`
      kept for source/`make install` users.
- [ ] **AppArmor profile**: companion to the existing systemd
      hardening. Distro-side, lives under `packaging/apparmor/`.
- [ ] **SELinux policy module**: same, for RHEL-family targets if
      anyone wants them.

---

## 9. Testing

- [ ] **Fuzz targets** (`cargo-fuzz`): SSTP framing, PPP option
      parsing, RADIUS attribute decode (the latter belongs in
      `radius-tokio`).
- [ ] **Conformance corpus** under `tests/fixtures/`: captured
      Windows-client and `sstpc` byte streams replayed against the
      state machine. Today's e2e tests run the real binaries; the
      replay harness lets CI run on a stock kernel with no
      privileged container.
- [ ] **Soak test**: 24 h `heaptrack` run with a synthetic client
      that opens/closes a session every N ms. Zero RSS growth at
      steady state is the gate.
- [ ] **Kernel matrix CI**: build + boot a minimal initramfs under
      QEMU for each LTS kernel we claim to support (currently
      6.12+) and run `tests/e2e.rs` with `--data-path kernel`
      against it. The current CI only covers the TUN fallback.
- [ ] **Multi-client scale test**: 10 k concurrent sessions on a
      single host with the synthetic client, measuring p99 control
      latency. Establishes a number to defend against regression.

---

## 10. Documentation

- [ ] **Interop matrix**: which clients and which RADIUS servers
      we've actually verified, and at what version. Lives under
      [docs/admin-guide.md](docs/admin-guide.md).
- [ ] **Migration guide from `pppd`-based stacks**: drop-in
      attribute mapping, what changes about accounting timing,
      what `Filter-Id` means in practice once §2 lands.
- [ ] **Architecture deep-dive**: extract the
      Architecture/Data-plane prose out of [CLAUDE.md](CLAUDE.md)
      into a contributor-facing [docs/architecture.md](docs/architecture.md)
      so the agent-facing file can stay terse.
- [ ] **Performance tuning guide**: `SO_REUSEPORT` knobs, kTLS
      cipher selection, `IRQbalance` / RPS guidance, NUMA
      placement. Aimed at >10 Gbps deployments.

---

## Explicit non-goals (will not be done)

These come up periodically; they are listed here so the answer is
discoverable.

- **A second VPN protocol** (L2TP/IPsec, OpenVPN, WireGuard,
  PPTP). One protocol done well beats five done badly. Operators
  needing protocol multiplexing should run multiple daemons.
- **A built-in user database** (SQLite, LDAP, file-backed).
  Authentication is RADIUS-only; everything else is the RADIUS
  server's problem.
- **A web/REST management UI** in-process. The control socket is
  the supported management surface; build a sidecar if you want
  HTTP.
- **A config-file parser**. CLI flags + env vars cover everything;
  if the flag surface grows past `--help` legibility, that's a
  signal to push policy into RADIUS, not to add a YAML parser.
- **Windows / macOS / BSD ports**. Linux-only, by design.
- **A reusable PPP library crate**. The PPP code is scoped to
  what SSTP needs; if a second consumer appears, extract then.
