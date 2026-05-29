# sstp-server

A high-performance, Linux-only [SSTP](MS-SSTP-spec.md) (Secure Socket Tunneling
Protocol, [MS-SSTP]) server in Rust. Terminates SSTP/TLS from Windows clients,
runs PPP, and forwards IP through the Linux kernel.

## Goals

- **Server only.** Accept SSTP clients on TCP/443, negotiate PPP, hand the
  resulting interface to the kernel for IP forwarding. No client mode, no
  cross-platform support.
- **Performance is the primary axis.** Targets are headline throughput and
  tail latency on the data path, and connection setup rate on the control
  path. Every design choice is judged against these.
- **Dependency light.** Prefer the standard library, `tokio`, and direct
  `aws-lc-sys` FFI over higher-level crates. New dependencies need
  justification.
- **Spec-faithful.** The wire format and state machine follow [MS-SSTP] as
  rendered in [MS-SSTP-spec.md](MS-SSTP-spec.md). Deviations are documented
  with a section reference.

## Non-goals

- Windows / macOS support, or any portability shims.
- A general-purpose PPP library. PPP support is scoped to what SSTP needs
  (LCP, authentication phase, IPCP/IPV6CP).
- Local user databases, config-file-driven user lists, or any auth backend
  other than RADIUS.
- A library/crate API surface. This repo is a daemon; reusable pieces can be
  extracted later if a second consumer appears.

## Architecture

### Runtime topology

- **Listener: `SO_REUSEPORT` + per-core `tokio` `LocalSet`.** One acceptor per
  worker, no shared accept queue, no `Arc<Mutex<...>>` on the read path.
  Connection state stays on the worker that accepted it; futures are
  `!Send` by construction.
- **Auth on a separate runtime.** RADIUS round-trips are unbounded and
  network-bound; running them off the I/O workers keeps the read path
  jitter-free. A small multi-threaded `tokio` runtime (or a dedicated
  `LocalSet` pinned to a non-I/O core) handles the auth phase, then hands the
  authenticated session back to the I/O worker that owns the TCP socket.
- **No global locks on steady-state packet flow.** Per-session state is owned
  by exactly one task; cross-worker signalling (shutdown, CoA-driven
  disconnect) goes through bounded MPSC channels, not shared mutable state.

### Data plane

The fastest data path on Linux is to keep bulk IP traffic out of userspace
entirely after IPCP completes:

1. SSTP frames are read from the TLS socket in userspace.
2. PPP control frames (LCP, auth, IPCP) are handled by the in-process PPP
   state machine.
3. Once IPCP converges, the session is bound to a kernel PPP unit via
   `/dev/ppp` (`PPPIOCNEWUNIT`, `PPPIOCATTCHAN`). The resulting `pppN`
   interface is owned by the kernel; routed IP traffic flows through the
   normal Linux forwarding path without per-packet userspace overhead.
4. Userspace continues to demultiplex incoming SSTP frames: data packets are
   written into the kernel PPP channel fd; control packets are handled in
   process.

This mirrors how `accel-ppp` achieves its throughput numbers and is the
constraint that drives the choice to implement PPP in-process rather than
shelling out to `pppd`. `pppd` spawns a process per session and routes every
data packet through a pty, which caps throughput and inflates memory per
session by orders of magnitude.

**v0.1 reality.** Mainline Linux has no generic userspace-channel API on
`/dev/ppp` — channels are registered only by in-kernel transport drivers
(`pppoe`, `pppol2tp`, `pptp`). Without our own kmod, the per-packet path
necessarily runs through userspace: the `pppN` unit fd is used
bidirectionally (read = TX, write = RX), the same model `pppd` uses over
a pty. We deliberately keep `pppN` (rather than a plain TUN device)
because the migration to a future kmod becomes a swap of the data-path
module rather than a redesign — the PPP unit lifecycle, NP-mode filtering,
header compression negotiation, and the `ip -s link show pppN` accounting
all carry over unchanged. The TUN alternative would save one kernel
module dependency but add a per-packet PPP-header strip/add in userspace
and force us to re-implement NP filtering by hand, for no win we'd
recoup later.

**Future kmod ABI.** The intended kernel-side interface for v0.x is
sketched in [kernel-abi/sstp.h](kernel-abi/sstp.h) as a draft UAPI
header, with a v0.1 lifecycle-only kmod skeleton under [kmod/](kmod/)
that builds against any Linux 6.12+ tree with `CONFIG_PPP=m`.
Userspace will hand the kernel a kTLS-equipped TCP fd plus the
negotiated PPP unit via an `SSTP_IOC_ATTACH` ioctl on `/dev/sstp`;
the kernel then registers an SSTP PPP channel against that unit and
runs the steady-state data path (kTLS decrypt → SSTP demux →
`ppp_input`) without userspace involvement. The header is
non-normative until the module is feature-complete; the current
kmod compiles, exercises attach/detach lifecycle and the session_fd
event surface, but stubs the per-frame demux and TX paths (TODOs
tagged `v0.1` in `kmod/sstp_demux.c` and `kmod/sstp_chan.c`).

### Crypto

- All cryptographic operations live in a single in-tree `crypto` module that
  wraps `aws-lc-sys` directly. No `ring`, no `rustls`, no `openssl` crate.
- TLS uses `aws-lc-sys`'s `libssl` directly through the `crypto` module's
  `SSL`/`SSL_CTX` newtypes. The rest of the codebase sees a safe
  `TlsStream` surface; `unsafe` is confined to the FFI wrappers, each block
  carrying a `// SAFETY:` comment.
- FFI handles (`SSL`, `SSL_CTX`, `EVP_MD_CTX`, `HMAC_CTX`, ...) are wrapped in
  newtypes whose `Drop` frees via the correct `*_free`.
- SSTP-specific crypto (Crypto Binding HMAC over CMK, CMK derivation from the
  inner-method MSK / TLS exporter per [MS-SSTP] §3.2.5.2) is implemented on
  top of those primitives in the same module.

### Authentication

- **Backend: RADIUS only**, via the sister crate
  [`radius-tokio`](https://github.com/ogital-net/radius-tokio) (BSD-2-Clause,
  same org). PPP authentication phase results — PAP credentials, CHAP /
  MS-CHAPv2 challenge/response, or EAP fragments — are translated to
  Access-Request attributes and forwarded.
- **EAP** is handled by the
  [`radius-tokio-eap`](https://github.com/ogital-net/radius-tokio/tree/main/crates/radius-tokio-eap)
  companion crate (PEAP, EAP-TLS, EAP-TTLS, EAP-MSCHAPv2). The PPP layer
  fragments/reassembles EAP-Message and otherwise stays out of method
  internals.
- **MPPE keys** required for the SSTP Crypto Binding come from the RADIUS
  reply (MS-MPPE-Send-Key / MS-MPPE-Recv-Key VSAs for MS-CHAPv2; EAP MSK for
  EAP methods). The auth task hands these to the session before it goes
  hot.
- **IP address assignment is RADIUS-driven.** The Access-Accept supplies
  `Framed-IP-Address` (RFC 2865 §5.8) and optionally `Framed-IP-Netmask`,
  `Framed-Route`, `Framed-MTU`, `MS-Primary-DNS-Server` /
  `MS-Secondary-DNS-Server`, `MS-Primary-NBNS-Server` /
  `MS-Secondary-NBNS-Server`. There is no in-process address pool. If the
  RADIUS reply omits `Framed-IP-Address`, the session is rejected; we do
  not synthesise addresses. IPv6 follows the same rule via
  `Framed-IPv6-Prefix` / `Framed-Interface-Id` (RFC 3162) when IPV6CP
  support lands.

### RADIUS attribute references

The Microsoft-vendor (vendor-ID 311) RADIUS attributes used by NPS / RRAS are
the interop surface for any SSTP server that wants to talk to existing
deployments. Canonical sources, in order of authority for *current* Windows
behavior:

- **[MS-RNAP] — Vendor-Specific RADIUS Attributes for NAP** (Microsoft Open
  Specification). The current normative definition of the MS-VSAs NPS emits
  and consumes: `MS-CHAP-Challenge`, `MS-CHAP-Response`, `MS-CHAP2-Response`,
  `MS-CHAP2-Success`, `MS-CHAP-Error`, `MS-MPPE-Send-Key`,
  `MS-MPPE-Recv-Key`, `MS-MPPE-Encryption-{Policy,Types}`, `MS-RAS-Vendor`,
  `MS-RAS-Version`, `MS-RAS-Client-{Name,Version}`, etc. Same Open
  Specifications program as [MS-SSTP]. Cite by section number in code.
- **RFC 2548 — Microsoft Vendor-specific RADIUS Attributes**. Original IETF
  Informational definition; MS-RNAP is a strict superset and wins on
  conflicts, but for the SSTP-adjacent attributes the two agree.
- **RFC 2759 — MS-CHAPv2**. The challenge/response algorithm and the
  AuthenticatorResponse string carried in `MS-CHAP2-Success`.
- **RFC 3079 — Deriving Keys for MPPE**. How `MS-MPPE-Send-Key` /
  `MS-MPPE-Recv-Key` are derived from the NT-hash + peer/auth challenges.
  This is the chain that feeds the SSTP Crypto Binding HMAC over CMK
  ([MS-SSTP] §3.2.5.2.3).
- **[MS-CHAP]** (Microsoft Open Specification). Restates RFC 2759 with
  Microsoft's clarifications; resolves RFC ambiguities.

Reference chain for the Crypto Binding code path:
RFC 2759 (CHAPv2) → RFC 3079 (MPPE key derivation) → [MS-RNAP] (wire
encoding of `MS-MPPE-{Send,Recv}-Key`) → [MS-SSTP] §3.2.5.2 (CMK derivation
from HLAK, HMAC over the call-connected packet).

For attribute *identifiers and on-wire encodings*, defer to the FreeRADIUS
`dictionary.microsoft` family — it's the de-facto cross-vendor reference
that NPS, FreeRADIUS, accel-ppp, strongSwan and hostapd all interop against.
We get it through `radius-tokio`'s vendored dictionary feature rather than
hand-rolling attribute numbers.

### `radius-tokio` features we depend on

Pinned set, kept minimal:

- `dict-rfc` (default) — base RFC 2865/2866/2868/3162 attributes.
- `dict-microsoft` — MS VSAs (RFC 2548 + MS-RNAP coverage).
- `radsec` — only if a deployment wants RADIUS-over-TLS to its RADIUS
  servers; otherwise off to skip the `libssl` bindgen step.
- `tracing` / `metrics` — gated behind matching cargo features on this
  crate so they propagate cleanly.

EAP methods come from `radius-tokio-eap` with the `peap`, `eap-mschapv2`,
`eap-tls`, and `eap-ttls` features. `eap-md5` is intentionally not enabled
(Windows SSTP clients don't offer it and it has no MSK, so no Crypto
Binding).

## Configuration

**CLI flags only. No config files.** Everything that varies per deployment
is a command-line flag; everything that's a secret is an environment
variable. `dotenvy` is loaded on startup for development convenience
(`.env` next to the binary, only if present) but is a no-op in production
where systemd / Kubernetes / etc. inject env vars directly.

Rationale: a config file is one more piece of state to reload, validate,
and schema-version. A daemon with ~15 knobs doesn't earn its keep. If the
flag surface grows past what fits in a `--help` screen, that's a signal to
push policy into RADIUS, not to add a config parser.

### Flags (first-pass, all parsed via `getopt-iter`)

```
-l, --listen <addr>        Listen address (default: [::]:443)
-c, --cert <path>           TLS certificate chain (PEM)
-k, --key <path>            TLS private key (PEM)
-r, --radius <host:port>    RADIUS auth server (repeatable)
-A, --acct <host:port>      RADIUS accounting server (repeatable, optional)
-t, --threads <n>           I/O worker count (default: auto, see below)
    --auth-threads <n>      Auth runtime threads (default: max(2, ncpus/4))
    --control-socket <path> Stats/admin socket (default: /run/sstp-server.sock)
    --no-control-socket     Disable the control socket entirely
    --log-format <fmt>      text | json | auto (default: auto)
    --log-file <path>       Log to file instead of stderr (still non-blocking)
-v                          Increase log verbosity (repeatable: -v, -vv, -vvv)
-q, --quiet                 Errors only
-h, --help                  Print usage
-V, --version               Print version
```

### Verbosity → log level mapping

| Flags  | Level    | What it includes                                 |
|--------|----------|--------------------------------------------------|
| (none) | `warn`   | Warnings and errors only                         |
| `-v`   | `info`   | Per-session lifecycle (accept, auth, teardown)   |
| `-vv`  | `debug`  | Control-plane state transitions (LCP, IPCP, ...)|
| `-vvv` | `trace`  | Per-frame control-plane tracing (never data plane) |
| `-q`   | `error`  | Errors only                                       |

`-q` and `-v` are mutually exclusive; later flag wins. Even at `-vvv`
there is no per-data-packet tracing — that's an eBPF / `tcpdump` job, not
the server's.

### Worker thread defaults

The `-t` / `--threads` flag overrides; the default is derived at startup:

- I/O workers: `available_parallelism()` from `std::thread`, minus auth
  threads, floored at 1. Each I/O worker pins to a `LocalSet` with its own
  `SO_REUSEPORT` listener socket.
- Auth runtime: `max(2, ncpus / 4)`, capped at the I/O worker count. The
  auth runtime is multi-threaded `tokio` (work-stealing) so a slow RADIUS
  server can't head-of-line block; I/O workers stay single-threaded
  per-core.

Deployments on dedicated hardware will commonly want `-t $(nproc)` minus
whatever the operator wants to leave for the kernel softirq / NAPI cores,
plus an `--auth-threads` override if RADIUS latency is unusual.

### Secrets

Never passed on the command line (visible in `ps`, leaks to shell
history). Env vars only:

| Variable                          | Purpose                                  |
|-----------------------------------|------------------------------------------|
| `SSTP_RADIUS_SECRET`              | Shared secret for `--radius` servers     |
| `SSTP_RADIUS_ACCT_SECRET`         | Shared secret for `--acct` servers (defaults to `SSTP_RADIUS_SECRET`) |
| `SSTP_TLS_KEY_PASSWORD`           | Optional passphrase for the TLS key      |
| `SSTP_RADSEC_CLIENT_KEY_PASSWORD` | Optional, only with `radsec` feature     |

`dotenvy::dotenv().ok()` runs once at startup before flag parsing so a
developer's `.env` populates the environment. In production the `.env` is
absent and the loader is a no-op. Secrets are zeroized after use where the
lifetime permits (the RADIUS secret stays resident — it's used per
request).

## Constraints and conventions

- **MSRV: Rust 1.83** (matches `radius-tokio`; needed for return-position
  `impl Trait` in traits and `async fn` in traits without `async-trait`).
- **Edition 2024.**
- **CLI parsing:** [`getopt-iter`](https://github.com/ogital-net/getopt-iter)
  (BSD-2-Clause, same org, zero dependencies). POSIX-style short options +
  Solaris-style long options embedded in the optstring
  (`"h(help)v+(verbose)..."`). No `clap`, no `structopt` — they pull a derive
  macro and a tree of dependencies for a handful of flags. `argv[0]`-driven
  program-name handling and `remaining()` for positional args cover what a
  daemon needs.
- **No config files.** All knobs are CLI flags; all secrets are env vars
  (see Configuration). `dotenvy` is loaded at startup for dev.
- **`unsafe`** is allowed in the `crypto` module's FFI wrappers, in the
  `/dev/ppp` ioctl wrappers, and in hot-loop bounds-check-elision sites
  (see Performance discipline below). Every block carries a `// SAFETY:`
  comment naming the invariant. `unsafe` outside those three categories
  needs explicit justification.
- **No `async-trait`.** Use native `async fn` in traits.
- **No `anyhow` / `eyre` in library-style modules.** Concrete error enums
  with `thiserror` are fine; the binary entry point may use a broader error
  type.
- **License: BSD-2-Clause**, matching `radius-tokio` and `getopt-iter`.

## Error handling

Error handling is deliberately spartan. The server is a packet forwarder;
threading `Result` through every internal call to model conditions that
*cannot happen* is overhead with no payoff. Two rules cover almost
everything:

1. **`Result` is for input validation at trust boundaries.** External
   inputs — wire-format SSTP frames, PPP options, RADIUS replies, CLI
   flags, env vars, file contents at startup — get parsed into typed
   internal forms and return `Result<_, ConcreteError>` on the way in.
   Once a value is in its validated internal form, downstream code
   consumes it infallibly.
2. **`assert!` / `debug_assert!` for invariants the implementation
   guarantees.** A library function returning a `Result` whose error
   variant *cannot occur* given how we call it gets asserted, not
   propagated. Example: `aws_lc_sys::RAND_bytes` returns `c_int`; per AWS-LC
   it only returns 0 on initialization failure of the global RNG, which
   for a long-running daemon either succeeded at startup or the process is
   already dead. Wrap it as:

   ```rust
   // SAFETY: out_ptr/len describe a valid &mut [u8].
   let rc = unsafe { RAND_bytes(out.as_mut_ptr(), out.len()) };
   assert_eq!(rc, 1, "RAND_bytes failed; AWS-LC RNG unusable");
   ```

   Same pattern for `EVP_DigestInit_ex`, `HMAC_Init_ex`, `SSL_CTX_new`
   on fixed methods, etc. — invariants we control, not user input.

Other rules that fall out of (1) and (2):

- **`unwrap()` / `expect()` are fine** when the operand is provably
  `Some`/`Ok`. Prefer `expect("explanation of why this is infallible")` so
  a future panic message names the broken invariant.
- **`debug_assert!` for hot-path invariants.** Anything checked per packet
  or per PPP option lives behind `debug_assert!` so release builds carry
  no overhead. Use `assert!` for once-per-session checks where the
  assertion cost is negligible and a panic is preferable to silent
  corruption (e.g. crypto length invariants).
- **No `?` chains for "can't happen" branches.** Don't sprinkle
  `.unwrap_or_else(|_| unreachable!())`; just assert and move on.
- **Panics at session scope, not process scope.** A per-session task
  panicking unwinds and tears down *that* session. The accept loop
  catches the join handle, increments `sstp_session_panics`, and
  continues. Process-wide invariants (RNG, crypto context init, TLS
  cert load) panic up to `main` and abort — there is no recovery.
- **Logging is the troubleshooting surface, not return values.** The
  authentication path in particular is logged generously at `info` and
  `debug` because RADIUS interop is where deployments break:
  - `info`: auth start (user, method, peer), auth result (accept /
    reject + reason if known), MPPE keys present? (boolean, not the
    keys themselves).
  - `debug`: each RADIUS request/response with attribute *names* (never
    secrets — `User-Password`, `MS-MPPE-*`, `Tunnel-Password` are
    redacted to `<len=N>`), retry/timeout events, EAP method
    negotiation, fragment reassembly progress.
  - `warn`: protocol violations from the client/RADIUS that we
    tolerate (unexpected attributes, malformed but non-fatal options).
  - `error`: only for things that abort the session.

  Outside the auth path, log volume is lower by an order of magnitude;
  the data path logs nothing per packet at any level.

## Observability

This is a daemon, not a library, so observability is built in unconditionally
rather than hidden behind cargo features. There's no exporter to choose at
compile time and no consumer to keep API-compatible; the operator's
interface is a Unix control socket and structured logs.

### Counters and gauges

- **`metrics` crate facade**, always compiled in. Recorder is installed at
  startup and feeds an in-process registry — no Prometheus HTTP endpoint,
  no statsd UDP socket, no exporter dependency tree. Operators scrape via
  the control socket (below).
- **No allocation on the data path.** Counter keys are `&'static str`;
  labels are pre-interned or `&'static`. Histograms are bucketed up-front
  so recording is `O(log buckets)` with no allocation.
- **Per-packet counters live in the kernel.** `sstp_bytes_{in,out}` are
  incremented per kernel-PPP write batch, not per packet; for
  packet-granular accounting use `ip -s link show pppN`. The server does
  not duplicate what the kernel already records for free.
- **Fixed event vocabulary**, prefixed `sstp_` (mirrors `radius_tokio_*` /
  `radius_tokio_eap_*` so a single scraper sees a consistent namespace
  across both crates). First-pass set:
  - `sstp_connections_accepted`, `sstp_connections_active` (gauge),
    `sstp_handshake_failures{reason=...}` (TLS, SSTP negotiation, PPP).
  - `sstp_auth_duration_seconds` (histogram), `sstp_auth_outcome{result=...}`.
  - `sstp_session_duration_seconds`, `sstp_session_teardown{reason=...}`.
  - `sstp_bytes_in` / `sstp_bytes_out` (per-batch, see above).
  - `sstp_crypto_binding_failures` (should always read zero in production).

### Control socket

HAProxy-style Unix-domain stats/admin socket, off the data plane, served
from a dedicated task on the auth runtime (never an I/O worker). Default
path `/run/sstp-server.sock`; overridable via `--control-socket <path>`,
disable with `--no-control-socket`.

- Line-oriented text protocol, one request → one response, designed to be
  driven by `socat`, `nc -U`, or a shell loop. No framing, no auth (Unix
  permissions on the socket file are the access control — `0660` by
  default, group-owned by the process group).
- Initial command set:
  - `show info` — version, uptime, worker count, active sessions.
  - `show stat` — all counters/gauges/histograms, one metric per line,
    pre-rendered strings so emission costs nothing on the hot path.
  - `show sess` — one line per active session: peer addr, username,
    assigned IP, bytes, duration, current PPP state.
  - `show sess <id>` — detailed dump for a single session.
  - `disable session <id>` — graceful teardown (PPP LCP Terminate-Request
    → SSTP Call-Disconnect).
  - `shutdown` — graceful drain: stop accepting, let active sessions
    finish, then exit.
- Cross-worker queries (`show sess`, `disable session`) fan out via the
  same bounded MPSC channels used for CoA disconnect; no shared mutable
  state.
- No HTTP, no JSON, no Prometheus exposition format in-tree. If an
  operator needs Prometheus they front the control socket with a tiny
  scraper sidecar — that's a 30-line script, not a build-time choice we
  should make for everyone.

### Logging

- **`tracing` is always compiled in**, with the standard `tracing` +
  `tracing-subscriber` + `tracing-appender` stack.
- **Non-blocking writer.** `tracing_appender::non_blocking` wraps the
  output sink (stderr by default) so a slow log consumer can never stall
  an I/O worker. The returned `WorkerGuard` is held in `main` for the
  lifetime of the process; on shutdown it flushes the buffer before
  return.
- **Bounded drop on backpressure.** The non-blocking appender's queue is
  sized at startup (default 8192 lines); when full, lines are dropped and
  `sstp_log_lines_dropped` is incremented. Dropping is the right answer
  for a packet-forwarding daemon — blocking the read path on a journal
  hiccup is worse than losing a debug line.
- **Span entry/exit on the control path only.** No spans on the
  steady-state packet loop. Even at `-vvv` (trace), per-data-packet events
  are disallowed — that's an eBPF / `tcpdump` job.
- **Output format:** human-readable to a TTY (`tracing_subscriber::fmt`
  with ANSI when `isatty(stderr)`), `json` when not a TTY (so systemd /
  journald / Loki get structured fields without a CLI flag). Override via
  `--log-format {text,json,auto}`.
- **Destination:** stderr by default. `--log-file <path>` switches to a
  file (still wrapped in the non-blocking appender; no log rotation
  in-process — that's `logrotate` / `journald` territory).

## Performance discipline

Performance is the primary axis. A few principles that override "idiomatic
Rust" defaults where they conflict:

- **`unsafe` for elided bounds checks is allowed**, but only when *both*
  conditions hold:
  1. We can guarantee the invariant from the surrounding code
     (`debug_assert!` it on the line above so a debug build catches
     violations).
  2. The compiler demonstrably can *not* elide the check on its own —
     verified by reading `cargo asm` / `cargo rustc -- --emit=asm` or
     `perf annotate`, not by hunch.

  `get_unchecked`, `get_unchecked_mut`, `unwrap_unchecked`,
  `slice::from_raw_parts`, etc. are tools, not crimes. Confined to hot
  loops in the SSTP demux path, PPP HDLC framing, and crypto primitive
  inner loops. Each call carries a `// SAFETY:` comment naming the
  invariant.

- **Target modern x86_64 and aarch64.** Reach for `std::arch` SSE/AVX2 /
  NEON intrinsics when an inner loop benefits — HDLC byte-stuffing
  scanning, PPP option scanning, CRC, constant-time compares all have
  obvious SIMD wins. Wrap intrinsics behind a small dispatch
  (`#[target_feature]` on a private helper, scalar fallback for
  cross-compile / older CPUs) so the binary still runs on baseline
  hardware while the fast path is used everywhere modern.
  - x86_64 baseline target: **x86-64-v3** (Haswell / AVX2 / BMI2).
    Encoded via `RUSTFLAGS="-C target-cpu=x86-64-v3"` in the release
    profile.
  - aarch64 baseline: **ARMv8.2-A + NEON** (Graviton 2, Ampere Altra,
    Apple Silicon, modern phone-class). `-C target-cpu=neoverse-n1` for
    the canonical cloud SKU.
  - Runtime CPU dispatch only where the baseline isn't enough (e.g.
    AES-NI / SHA-NI presence is checked once at startup; the result is
    a `static AtomicBool` so the dispatch is branch-predictor-friendly).

- **Allocation discipline.** No allocation on the steady-state packet
  path. Per-connection state is allocated once at session accept and
  reused for the connection's lifetime. Bytes flow through `BytesMut` /
  `Bytes` so demuxed PPP frames are zero-copy views, not owned vectors.
  Confirm with `dhat` or `heaptrack` on the bench harness; a non-zero
  per-packet allocation count is a regression.

- **`#[inline]` is data-driven.** Don't sprinkle it. Add it only where a
  benchmark (or `perf` profile) shows the call overhead matters. The
  default cross-crate inliner does the right thing 95% of the time;
  `#[inline(always)]` is a last resort for things like CRC step
  functions and HMAC inner-block routines.

- **Branch hints sparingly.** `std::hint::likely` / `unlikely` (when
  stabilized) or `cold` attributes on error paths only. Profile-guided
  optimization beats hand-placed hints; if PGO is on the table later,
  most hand hints come back out.

## Repository layout

Current state is a `cargo new` skeleton. Target layout as modules land:

```
src/
  main.rs             # binary entry, runtime construction
  cli.rs              # getopt-iter flag parsing, env-var loading
  crypto/             # aws-lc-sys wrappers (TLS, HMAC, hashes, RNG)
  sstp/               # SSTP framing, control messages, state machine
  ppp/                # in-process PPP control plane (LCP, auth, IPCP/IPV6CP)
  kppp/               # /dev/ppp ioctl wrappers, kernel PPP unit lifecycle
  auth/               # PPP-auth <-> RADIUS bridge (radius-tokio client)
  session/            # per-connection state, lifecycle, shutdown
  control/            # Unix control socket, stats/admin command dispatch
  net/                # SO_REUSEPORT listener, per-core LocalSet plumbing
kernel-abi/
  sstp.h              # DRAFT UAPI for the future SSTP kmod (see Data plane)
MS-SSTP-spec.pdf      # upstream spec (do not edit)
MS-SSTP-spec.md       # markdown render of the spec, regenerated from PDF
```

## Working with the spec

The authoritative reference is [MS-SSTP-spec.md](MS-SSTP-spec.md) (rendered
from [MS-SSTP-spec.pdf](MS-SSTP-spec.pdf) with `pymupdf4llm`). When citing
the spec in code or commit messages, reference section numbers (e.g.
"§2.2.7 Crypto Binding Attribute") so the citation survives spec revisions.
Regenerate the markdown after replacing the PDF:

```bash
/tmp/pdfvenv/bin/python -c "import pymupdf4llm; open('MS-SSTP-spec.md','w').write(pymupdf4llm.to_markdown('MS-SSTP-spec.pdf'))"
```

## Build checklist

Ordered roughly by dependency. Each milestone should land as a coherent
PR with tests where the surface allows. Check items off as they merge.

### M0 — Project scaffolding
- [x] `Cargo.toml` metadata: edition 2024, `rust-version = "1.85"`
      (bumped from the originally-targeted 1.83 because edition 2024
      requires 1.85), BSD-2-Clause, `repository`, `description`.
- [x] `clippy.toml` + `deny.toml` mirroring `radius-tokio` posture
      (warn on `unsafe_op_in_unsafe_fn`, deny on unauthorized licences).
- [x] CI workflow: `cargo fmt --check`, `cargo clippy -- -D warnings`,
      `cargo test`, `cargo deny check`, Linux-only matrix.
- [x] `cli.rs` skeleton: `getopt-iter` flag parsing matching the
      Configuration table; `--help`/`--version` work; `dotenvy::dotenv().ok()`.
      `--version` also reports the git short SHA and commit date via a
      `vergen-git2` build script.
- [x] `main.rs` boots `tokio` runtime(s), installs the `tracing` subscriber
      with the non-blocking appender, holds the `WorkerGuard`, exits clean
      on SIGINT/SIGTERM.

### M1 — Crypto module
- [x] `crypto/ffi.rs`: newtypes around `aws-lc-sys` handles (`EVP_MD_CTX`,
      `HMAC_CTX`, `SSL`, `SSL_CTX`, `BIO`, …) with correct `Drop` impls.
- [x] Hash + HMAC primitives (SHA-1, SHA-256) used by SSTP and PPP-auth.
- [x] RNG wrapper (`RAND_bytes`).
- [x] TLS server: `SSL_CTX` builder loading cert chain + key from PEM,
      `TlsAcceptor`/`TlsStream` surface usable from `tokio`.
- [x] **TLS exporter** (`SSL_export_keying_material`) — feeds the SSTP
      Crypto Binding CMK derivation ([MS-SSTP] §3.2.5.2).
- [x] Unit tests + AddressSanitizer job covering every `unsafe` block.

### M2 — SSTP framing & state machine
- [x] Packet codec: encrypted-data and control packet headers ([MS-SSTP]
      §2.2.1–2.2.2), zero-copy parse from a `BytesMut`.
- [x] Attribute encode/decode: `Encapsulated-Protocol-Id`,
      `Status-Info`, `Crypto-Binding`, `Crypto-Binding-Req`
      (§2.2.4–2.2.7).
- [x] Control message types: `Call-Connect-Request`, `-Ack`, `-Nak`,
      `Call-Connected`, `Call-Abort`, `Call-Disconnect`,
      `Echo-Request`/`-Response` (§2.2.9–2.2.14).
- [x] Server state machine (§3.2): `Call_Disconnected` →
      `Server_Call_Connected_Pending` → `Server_Call_Connected`, with
      hello timer and abort handling.
- [x] Crypto Binding verification: HMAC over the Call-Connected packet
      using CMK derived from HLAK (§3.2.5.2.3). Constant-time compare.
- [ ] Conformance tests against captured Windows client traces (kept
      under `tests/fixtures/`).

### M3 — In-process PPP control plane
- [x] HDLC-like framing (no async-map negotiation; SSTP carries PPP raw).
- [x] LCP: Configure-Request/-Ack/-Nak/-Reject, Terminate-Request,
      Echo-Request/-Reply, Code-Reject.
- [x] Auth phase dispatch: PAP, CHAP, MS-CHAPv2, EAP (just the
      fragment/reassembly layer; methods live in RADIUS).
- [x] IPCP: Configure exchange for `Framed-IP-Address` /
      `MS-Primary-DNS-Server` etc. from the auth result.
- [ ] (Deferred) IPV6CP — see Open questions.

### M4 — RADIUS bridge
- [x] `radius-tokio` client wired into the auth runtime with
      `dict-rfc` + `dict-microsoft` enabled.
- [x] PAP → Access-Request translation; Access-Accept → session bring-up.
- [x] MS-CHAPv2: `MS-CHAP-Challenge` + `MS-CHAP2-Response` →
      Access-Request; harvest `MS-MPPE-Send-Key`/`-Recv-Key` (RFC 3079)
      from Access-Accept for the Crypto Binding HLAK.
- [x] EAP pass-through (no `radius-tokio-eap` dep): RADIUS-side
      fragmentation via `radius_tokio::eap::{fragments,reassemble}`,
      `State` echoed across Access-Challenge rounds, terminal
      Accept/Reject projected the same as PAP/MS-CHAPv2. Method
      internals (PEAP, EAP-TLS, EAP-TTLS, EAP-MSCHAPv2) live in the
      RADIUS server — we just shuttle EAP-Message bytes between the
      PPP peer and the authenticator.
- [x] Accounting: Start / Interim-Update / Stop with byte counters
      pulled from the kernel PPP unit, not the userspace path.
      Implemented in `src/auth/accounting.rs` as a tokio-UDP
      `AcctClient` with `(peer, identifier)` correlation and
      RFC 5080 retry semantics. Byte / packet counters are supplied
      by the caller; M6 will sample them via `rtnetlink`
      `IFLA_STATS64` against `pppN`.
- [x] CoA / Disconnect-Request receiver → session teardown via MPSC
      channel to the owning I/O worker.
      v0.1: parser + responder live in `src/auth/coa.rs`
      (`CoaListener` + `Handler` trait). The MPSC handoff to the
      session map is M6 work — today the handler is a caller-supplied
      closure that can return ACK/NAK with an RFC 3576 Error-Cause.

### M5 — Kernel PPP data plane
- [x] `/dev/ppp` ioctl wrappers (`PPPIOCNEWUNIT`, `PPPIOCATTCHAN`,
      `PPPIOCGCHAN`, `PPPIOCSMRU`, `PPPIOCSFLAGS`) with `// SAFETY:`
      comments on every `unsafe` block. Const-fn `_IO`/`_IOR`/`_IOW`/
      `_IOWR` ports pinned by a numerical compile-time test against
      `<linux/ppp-ioctl.h>`.
- [ ] Channel fd: write user-plane PPP frames demuxed from SSTP into the
      kernel channel; control frames stay in userspace.
      **NOTE:** mainline Linux has no generic userspace-channel
      interface — channels are registered by kernel transport drivers
      (`pppoe`, `pppol2tp`, `pptp`). Without a custom kernel module,
      the data path stays in userspace and uses the unit fd
      bidirectionally (read = TX, write = RX), the same model `pppd`
      uses over a pty. Per-packet zero-copy via the kernel would need
      a new in-tree channel driver or eBPF; out of scope for v0.1.
- [x] Unit fd: create `pppN` netdev, push `Framed-IP-Address` and routes
      via netlink. Hand-rolled `NETLINK_ROUTE` client in
      `src/kppp/netlink.rs` (no `rtnetlink` crate dependency — the
      surface is three message types and the operations are off the
      data path). Supports `RTM_NEWADDR` (P2P address pair), link
      `IFF_UP`, and `IFLA_MTU`; `Framed-Route` (`RTM_NEWROUTE`)
      deferred to when a deployment needs it.
- [x] Teardown path: unit deletion on session close, fd cleanup on
      panic/SIGTERM.
      `Unit::close()` is the explicit teardown call (debug-traced);
      `Drop` traces and lets `OwnedFd` close the `/dev/ppp` fd,
      which removes `pppN`. A panicking session task therefore
      releases its netdev as it unwinds.

### M6 — Session glue & lifecycle
- [x] Per-connection task on the accepting I/O worker that owns the
      TCP socket, TLS state, SSTP state machine, and PPP control plane.
      v0.1: scaffold in `src/session.rs`. `session::run` is spawned via
      `tokio::task::spawn_local` from the accept loop, holds an RAII
      `RegistrationGuard` so the global `Registry` cannot leak entries
      on panic, and selects on `(stream, control_rx, drain_rx)`. The
      TLS handshake → SSTP demux → PPP drive loop is the next TODO
      inside that task; the structural plumbing around it is done.
- [x] Bounded MPSC for cross-worker control: shutdown, CoA disconnect,
      `disable session` from the control socket.
      `SessionHandle` wraps an `mpsc::Sender<ControlCommand>` (depth 4,
      `try_send` drops on full / closed) and is cloneable across
      runtimes. `Registry::broadcast_disconnect` fans out to every
      live session; targeted teardown is `Registry::get(id).try_send`.
- [x] Graceful drain: stop accepting on SIGTERM / `shutdown` command,
      send PPP LCP Terminate-Request, wait up to N seconds, then exit.
      `main::run` broadcasts the shutdown signal (workers stop
      accepting), then `Registry::broadcast_disconnect(ServerShutdown)`
      asks every session to tear down. Both `main` and each worker's
      accept loop bound the wait at `DRAIN_GRACE` (10 s) before
      abandoning stuck tasks. The actual PPP `LCP Terminate-Request`
      lands when the session task drives the PPP FSM end-to-end.

#### M6 MVP roadmap (first end-to-end PAP login)

The pieces below are what stand between today's scaffold session
task (TCP accept → peek-and-drop) and a Windows / `sstpc` client
completing an unauthenticated PAP handshake against the server.
Tracked here as a checklist rather than inlined into the M6 box
because each is a self-contained PR-sized unit; the end-to-end
integration test in `tests/e2e.rs` (`sstpc_pap_login`) graduates
its assertions as each item lands.

Ordered by dependency:

- [x] **M6a — TLS terminate in the session task.** Replace the
      placeholder `stream.peek()` with `crypto::tls::SslContext::accept`
      against an `SslContext` constructed once at startup from the
      `--cert` / `--key` flags and cloned per worker. Failure logs at
      `info` with `sstp_handshake_failures{reason="tls"}` incremented;
      session ends. The cert / key load belongs in `main::run` so a
      bad PEM aborts startup rather than every connection.
- [x] **M6b — SSTP HTTPS preamble (§3.2.4.1).** Read the HTTP/1.1
      request line + headers from the TLS stream, validate
      `SSTPCORRELATIONID` + `Content-Length: 18446744073709551615`,
      send the canned `HTTP/1.1 200` response, then hand the rest of
      the byte stream to the SSTP framing codec. Bounded read buffer
      (4 KiB header cap, RFC 7230 §3.2.5 alignment); reject anything
      else with `400 Bad Request` and `sstp_handshake_failures{
      reason="http"}`.
- [x] **M6c — Drive `sstp::StateMachine` from the session task.**
      `drive_sstp` in [src/session.rs](src/session.rs) selects on
      `(tls_read, control_rx, drain_rx, ssm_timers)`, feeds inbound
      packets through `Packet::parse` + `parse_control` into the
      state machine, and applies each `StepOut` via `apply_step`
      (write `tx_buf[..send_len]`, arm at most one
      `tokio::time::Sleep` per `Timer`, surface `NotifyHigher`,
      honour `Terminate`). `Truncated` / `LengthMismatch` parse
      errors are treated as "need more bytes" against a `Vec<u8>`
      reassembly buffer; other parse errors abort the session. PPP
      data bodies are still dropped — wiring lands in M6d.
- [x] **M6d — Drive the PPP control plane.** New
      [src/ppp/driver.rs](src/ppp/driver.rs) houses `LcpServer` and
      `IpcpServer`, each wrapping `super::fsm::Fsm` with the
      server-side option-negotiation policy ([RFC 1661] §6, [RFC 1332]
      §3, [RFC 1877] §1). LCP advertises `Auth-Protocol = PAP` only
      for v0.1; CHAP / MS-CHAPv2 / EAP plumbing exists in
      `super::auth` but is not yet wired through the orchestrator.
      The top-level `Ppp` driver orchestrates Establish → AuthPending
      → AuthInFlight → Network → Dead, surfaces PAP credentials via
      `PppEvent::NeedPapAuth { peer_id, password }` and accepts the
      verdict back through `Ppp::on_auth_result(AuthVerdict)`.
      Inbound PPP frames flow as `ProtocolId::Lcp` / `::Pap` /
      `::Ipcp` SSTP data packets; outbound frames are encoded with
      uncompressed Address/Control/Protocol prefixes ready to be
      wrapped in an SSTP data packet. Wired into
      [src/session.rs](src/session.rs) `drive_sstp`: the
      `NotifyHigher::StartPpp` notification (emitted when SSTP sends
      `Call-Connect-Ack`) instantiates `Ppp` and calls `Ppp::open`;
      inbound `Packet::Data` payloads feed `Ppp::on_frame`; a second
      `Pin<Box<Sleep>>` slot tracks the active PPP restart timer
      (`TimerOwner::Lcp` or `::Ipcp`). PAP credentials are handed to
      a `oneshot::Sender<AuthVerdict>` which v0.1 fulfils
      in-process with a `Reject("auth backend not wired (M6e)")` —
      M6e replaces the rejector with a `radius-tokio` round-trip
      without changing the oneshot signature.
- [ ] **M6e — RADIUS bridge integration.** `auth::client::authenticate_pap`
      runs on the auth runtime; on Access-Accept the resulting
      `AuthAccept` (with `Framed-IP-Address`, optional DNS / WINS,
      MPPE keys if present) is sent back to the session task via a
      `oneshot`. The session task then drives IPCP with those
      addresses and emits SSTP `Call-Connected` (M6f).
- [ ] **M6f — SSTP Crypto Binding `Call-Connected`.** Derive HLAK
      from the TLS exporter (no MSK with PAP, so HLAK is the EKM
      bytes per [MS-SSTP] §3.2.5.2.1.1); compute the
      `Crypto-Binding` HMAC; build and send the `Call-Connected`
      packet. State machine transitions to `Server_Call_Connected`.
- [ ] **M6g — Kernel PPP unit bring-up.** Allocate a `pppN` unit via
      `kppp::Unit::new`, push the negotiated MRU and IP addresses
      through `kppp::netlink`. For v0.1 the userspace data path keeps
      reading frames from TLS, demuxing, and writing PPP packets to
      the unit fd (`pppd`-over-pty model). Tear down the unit on
      session close.
- [ ] **M6h — Graduate the integration test.** Replace the soft
      forward-looking assertions in `tests/e2e.rs` with positive
      checks: `radius.seen()` contains exactly one Access-Request
      with `username == "alice"` and `pap_outcome == Match`; `sstpc`
      exits 0; the kernel has a `pppN` interface with the assigned
      `Framed-IP-Address`. Drop the runtime skip on root / `/dev/ppp`
      from the harness and instead require those preconditions in
      the dev container.

### M7 — Control socket
- [x] Unix socket bind at `--control-socket` path, `0660` perms.
      `src/control.rs::serve` removes any stale socket file, binds
      `UnixListener`, sets `PermissionsExt::from_mode(0o660)`, and
      removes the file on graceful exit. Logged at info.
- [x] Line-oriented dispatcher running on the auth runtime.
      Spawned from `main::run` on the auth runtime via
      `tokio::spawn`; per-connection tasks use `BufReader::read_line`
      with a 1 KiB line cap. Every command produces a response
      terminated by an empty line; `shutdown` closes the connection.
- [x] Commands: `show info`, `show stat`, `show sess`, `show sess <id>`,
      `disable session <id>`, `shutdown`. Plus `help`. Unknown
      commands return `Error: unknown command (try 'help')` and the
      connection stays open. `shutdown` reuses the same
      `broadcast::Sender<()>` the SIGTERM path uses, so the drain
      logic in `main::run` is shared.
- [x] Pre-rendered metric snapshot to keep `show stat` allocation-free
      on the registry side. Metrics live in `src/metrics.rs` as
      `pub static Counter`/`Gauge` newtypes around `AtomicU64`/`I64`
      with `Ordering::Relaxed`. Call sites do
      `metrics::CONNECTIONS_ACCEPTED.inc()` \(no `&'static str`
      lookup, no recorder install\); `metrics::render_stats` is the
      only allocator and runs once per `show stat`. Wired into the
      session accept/teardown path (`session::spawn_handle` and the
      `RegistrationGuard`).

### M8 — Benchmarks & hardening
- [ ] `benches/` with a synthetic SSTP client to measure connection-setup
      rate (control plane) and steady-state throughput (data plane via
      kernel PPP).
- [ ] Fuzz targets for SSTP framing and PPP option parsing (`cargo-fuzz`,
      mirroring `radius-tokio`'s setup).
- [ ] Long-run soak test (24h) with `valgrind`/`heaptrack` on a debug
      build to confirm zero growth at steady state.
- [ ] systemd unit file with appropriate `CapabilityBoundingSet`
      (`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`), `NoNewPrivileges`,
      `ProtectSystem=strict`, etc.

### M9 — Release prep
- [ ] `README.md` for end users (separate from this document).
- [ ] `CHANGELOG.md` started.
- [ ] Interop matrix documented: Windows 10/11 built-in client,
      Windows Server RRAS, at least one third-party client (SoftEther,
      sstp-client).
- [ ] v0.1.0 tag.

## Open questions

- IPv6CP support timing relative to IPv4 IPCP.
- Whether to expose `--threads`/`--auth-threads` as percentages of
  `available_parallelism()` in addition to absolute counts.
