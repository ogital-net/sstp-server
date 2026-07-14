# Administrator's guide

Operator-facing documentation for `sstp-server`: installing it,
running it, pointing it at a RADIUS server, and keeping an eye on
it once it's live. Audience: system administrators deploying the
daemon, not developers working on it. For internals (data path,
kernel module ABI, packet flow), see [data-path.md](data-path.md).

## What sstp-server does

`sstp-server` terminates Microsoft's [SSTP] (Secure Socket
Tunneling Protocol) on Linux. Windows clients (the built-in
"SSTP" VPN type), `sstpc` (the `sstp-client` package), and any
third-party SSTP client speak TLS-over-TCP/443 to the daemon;
the daemon runs PPP authentication against a RADIUS server,
hands the per-session interface to the Linux kernel, and from
that point IP traffic is forwarded through normal kernel
plumbing.

Two data-path backends:

- **Kernel** (preferred): the [`sstp.ko`](../kmod/) kernel module
  registers a PPP channel against a kTLS-equipped TCP socket;
  steady-state IP traffic never enters userspace.
- **TUN** (fallback): a plain `/dev/net/tun` device, with
  TLS+PPP framing done in userspace. Available on any modern
  Linux without out-of-tree modules.

`--data-path auto` picks the kernel backend when `/dev/sstp` is
loaded and a kTLS-eligible cipher is negotiated; otherwise it
falls back to TUN with an `info`-level log line. There's nothing
to configure beyond `--data-path` itself.

[SSTP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/

## Installation

### From the Debian package

```sh
sudo apt install ./sstp-server_*.deb ./sstp-server-dkms_*.deb
```

The two packages do separate things:

- **`sstp-server`** installs the daemon at `/usr/sbin/sstp-server`,
  the systemd unit at `/lib/systemd/system/sstp-server.service`,
  and a default environment file at
  `/etc/sstp-server/sstp-server.env`. The `postinst` creates a
  system user `sstp-server:sstp-server` for the daemon to run as.
- **`sstp-server-dkms`** ships the kernel module sources under
  `/usr/src/sstp-<version>/` and registers them with DKMS so the
  module rebuilds automatically against every installed kernel.
  Requires the matching `linux-headers` package.

The daemon will run without the DKMS package — it just falls
back to the TUN data path. Install it for production
deployments where throughput matters.

### From source

```sh
git clone https://github.com/ogital-net/sstp-server
cd sstp-server
make build              # cargo build --release
sudo make install       # /usr/sbin, /etc/sstp-server, /lib/systemd/system
sudo make kmod          # build the kmod against the running kernel
sudo make kmod-install  # modules_install + depmod
sudo modprobe sstp
```

The Makefile honours `DESTDIR`, `PREFIX`, `SYSCONFDIR`,
`UNITDIR`, `KDIR` and the rest of the GNU layout variables. See
the top of [`Makefile`](../Makefile) for the full list.

Build prerequisites: Rust ≥ 1.85, cmake, clang (for `aws-lc-sys`
bindgen), pkg-config. Kernel headers are only needed for the
kmod.

## First-run checklist

To accept a client, you need:

1. A **TLS certificate** the client trusts. Windows ships with the
   Microsoft Trusted Root store; for production use a Let's
   Encrypt or commercial cert covering the public hostname clients
   will dial. Self-signed works for testing if you import the cert
   into the client's trust store first.
2. A **RADIUS server** reachable from the daemon, with a shared
   secret and at least one user configured to return
   `Framed-IP-Address`. Any RADIUS implementation works
   (FreeRADIUS, NPS, accel-ppp's built-in server, the in-tree
   [`examples/dev-radius.rs`](../examples/dev-radius.rs) for
   testing).
3. A **routable IPv4 address pool** the RADIUS server hands out
   via `Framed-IP-Address`, plus IP forwarding enabled
   (`sysctl net.ipv4.ip_forward=1`) on the SSTP server.
4. A **server-side IPv4** for the daemon to use as the local end
   of every `pppN` point-to-point pair (`-i / --local-ip`). This
   is just a peer address for the netdev; it doesn't need to be
   routable on its own.

Edit `/etc/sstp-server/sstp-server.env`:

```sh
SSTP_RADIUS_SECRET=your-radius-secret-here

OPTS=--listen [::]:443 \
     --cert /etc/sstp-server/server.crt \
     --key  /etc/sstp-server/server.key \
     --radius 10.0.0.5:1812 \
     --acct   10.0.0.5:1813 \
     --local-ip 10.255.255.1 \
     --control-socket /run/sstp-server/sstp-server.sock \
     -v
```

(systemd's `EnvironmentFile` parser does not honour shell-style
backslash continuation; in the actual file `OPTS=` must be on a
single physical line. The default file ships that way; the
breakdown above is for readability.)

Then:

```sh
sudo systemctl enable --now sstp-server
journalctl -u sstp-server -f
```

A successful first connection logs roughly:

```
sstp-server[1234]: data-path: kernel
sstp-server[1234]: listening on [::]:443
sstp-server[1234]: TLS handshake ok peer=203.0.113.4:51022
sstp-server[1234]: PAP RADIUS Access-Accept ip=10.99.0.42 user=alice
sstp-server[1234]: kernel PPP unit attached ifname=ppp0
```

## TLS certificates

The daemon reads `--cert` (PEM chain) and `--key` (PEM private
key) once at startup and once per `SIGHUP`. Both files must be
readable by the `sstp-server` group; the standard layout is
`root:sstp-server`, mode `0644` for the cert and `0640` for
the key. The Debian package's `postinst` already enforces
those permissions on `/etc/sstp-server/`.

### Hot reload via SIGHUP

`SIGHUP` rebuilds the in-process `SSL_CTX` from the on-disk
PEM files and atomically swaps it under an `RwLock`. The
swap **does not tear down active sessions** — each live
connection holds an `SSL_CTX_up_ref` against the old context
for the lifetime of its TLS state, and only the **next**
incoming TCP connection picks up the new certificate. There
is no listener restart, no TCP socket churn, no bump in
`sstp_handshake_failures`.

If the new cert/key fails to parse, the swap is skipped, the
old context stays in place, and the daemon logs `SIGHUP TLS
reload failed; keeping current certificate` at `warn` —
clients keep connecting against the previous cert, no service
interruption.

To trigger a reload manually:

```sh
sudo systemctl kill -s HUP sstp-server.service
```

(Avoid `kill -HUP $(pidof sstp-server)` on systemd hosts —
`systemctl kill` respects the unit's `KillMode` and only
targets the main PID.)

### Let's Encrypt with certbot

The package ships a ready-to-use certbot deploy hook at
`/usr/share/sstp-server/certbot-deploy-hook.sh`. It copies the
renewed `fullchain.pem` and `privkey.pem` from
`$RENEWED_LINEAGE` into `/etc/sstp-server/server.{crt,key}`,
sets `root:sstp-server` ownership with the correct modes, and
sends `SIGHUP` to the running unit.

Initial issue + wiring (one-shot, run as root):

```sh
# 1. Issue the certificate. Use whichever certbot plugin
#    fits your DNS / web setup; standalone works if nothing
#    else is on :80.
sudo certbot certonly --standalone -d vpn.example.com

# 2. Install it for the daemon and pick up new renewals
#    automatically.
sudo /usr/share/sstp-server/certbot-deploy-hook.sh \
    RENEWED_LINEAGE=/etc/letsencrypt/live/vpn.example.com

# 3. Tell certbot to run the hook on every renewal.
sudo sh -c 'cat >> /etc/letsencrypt/renewal/vpn.example.com.conf <<EOF
renew_hook = /usr/share/sstp-server/certbot-deploy-hook.sh
EOF'
```

(Adding `renew_hook` to the per-cert renewal config is
preferred over a global `--deploy-hook` — it scopes the
SIGHUP to the right service if you also serve other things
out of certbot.)

Renewals after that are fully automatic: certbot's systemd
timer runs `certbot renew` twice daily, the hook fires only
when a cert actually rotates, and the daemon picks up the new
material on `SIGHUP` without dropping a single VPN session.

The hook honours three environment variables for non-default
deployments: `SSTP_CERT_DIR` (default `/etc/sstp-server`),
`SSTP_GROUP` (default `sstp-server`), `SSTP_UNIT` (default
`sstp-server.service`).

### Self-signed certs (testing only)

For lab use:

```sh
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout /etc/sstp-server/server.key \
    -out    /etc/sstp-server/server.crt \
    -subj   "/CN=vpn.lab.example"
sudo chgrp sstp-server /etc/sstp-server/server.{crt,key}
sudo chmod 0640 /etc/sstp-server/server.key
sudo chmod 0644 /etc/sstp-server/server.crt
```

Import the resulting `server.crt` into the Windows client's
**Trusted Root Certification Authorities** store (Computer
account, not user account) before dialling — Windows fails
the SSTP handshake silently on cert validation errors.

## Command-line reference

The full flag set, also visible via `sstp-server --help`. All
flags have a short and a long form.

| Short | Long                    | Default              | Notes                                                          |
|-------|-------------------------|----------------------|----------------------------------------------------------------|
| `-l`  | `--listen <addr>`       | `[::]:443`           | TCP listen socket. Use a specific IP to bind one interface.    |
| `-c`  | `--cert <path>`         | *required*           | TLS certificate chain, PEM.                                    |
| `-k`  | `--key <path>`          | *required*           | TLS private key, PEM. Set `SSTP_TLS_KEY_PASSWORD` if encrypted.|
| `-r`  | `--radius <host:port>`  | *required*           | RADIUS auth server. Repeatable; tried in order on failure.     |
| `-A`  | `--acct <host:port>`    | none                 | RADIUS accounting server. Repeatable. Optional.                |
| `-i`  | `--local-ip <ipv4>`     | *required*           | Server-side IPv4 used as the P2P local on every `pppN`.        |
| `-N`  | `--nas-identifier <id>` | hostname             | Sent as `NAS-Identifier`. Empty string opts out.               |
| `-D`  | `--data-path <mode>`    | `auto`               | `auto` / `kernel` / `tun`. `kernel` refuses to fall back.       |
| `-M`  | `--auth-method <m>`     | `pap`                | `pap` / `chap` / `mschapv2`. Advertised to the client in LCP.  |
| `-t`  | `--threads <n>`         | auto                 | I/O worker count (one `LocalSet` per worker, `SO_REUSEPORT`).  |
| `-T`  | `--auth-threads <n>`    | `max(2, ncpus/4)`    | Threads for the RADIUS / control runtime.                      |
| `-s`  | `--control-socket`      | `/run/sstp-server.sock` | Path to the admin Unix socket.                              |
| `-n`  | `--no-control-socket`   | n/a                  | Disable the control socket entirely.                           |
| `-x`  | `--no-mss-clamp`        | n/a                  | Disable TCP MSS clamping on `pppN` egress.                     |
| `-F`  | `--log-format <fmt>`    | `auto`               | `text` / `json` / `auto` (json when stderr is not a TTY).      |
| `-L`  | `--log-file <path>`     | stderr               | Logs go through a non-blocking appender; rotate via logrotate. |
| `-u`  | `--user <name>`         | none                 | Drop privileges after binding. Daemon must be started as root. |
| `-g`  | `--group <name>`        | user's primary       | Group to drop to.                                              |
| `-v`  |                         | `warn`               | Repeat for `info` / `debug` / `trace`. Trace is control plane only. |
| `-q`  | `--quiet`               | `warn`               | Errors only. Mutually exclusive with `-v`; later flag wins.    |
| `-h`  | `--help`                |                      |                                                                |
| `-V`  | `--version`             |                      | Reports version + git short SHA + commit date.                 |

### Required flags

`-c`, `-k`, `-r`, and `-i` are required. Everything else has a
default that's reasonable for a single-listener single-RADIUS
deployment.

### Multiple RADIUS servers

`--radius` is repeatable. Servers are tried in order; an
authoritative `Access-Reject` from any server short-circuits
(no policy fallback), but transport errors (timeout, ICMP
unreachable, malformed reply) cause the bridge to move on to
the next server. The shared secret applies to every
`--radius` entry — there is no per-server secret.

`--acct` works the same way: repeatable, tried in order. The
accounting secret defaults to `SSTP_RADIUS_SECRET`; set
`SSTP_RADIUS_ACCT_SECRET` to override.

### Authentication method

`--auth-method` controls what the daemon advertises to the
client during LCP:

- `pap` — PAP. Cleartext username/password over TLS. Simplest;
  required if you're using the EAP-TTLS / PEAP class of
  authenticators that expect cleartext inside the tunnel.
- `chap` — CHAP-MD5 ([RFC 1994]). MD5 challenge/response. The
  RADIUS server gets `CHAP-Password` + `CHAP-Challenge` to
  validate.
- `mschapv2` — MS-CHAPv2 ([RFC 2759]). Required by Windows
  clients that won't accept PAP. Yields MPPE keys for the
  SSTP Crypto Binding ([MS-SSTP] §3.2.5.2).

Pick the strongest method your RADIUS server supports for the
user database you're terminating against.

### Privilege drop

`-u sstp-server -g sstp-server` after binding TCP/443 keeps the
daemon running as an unprivileged user with `CAP_NET_ADMIN`
retained for `/dev/ppp` and netlink. The systemd unit shipped in
the Debian package handles this via `User=` /
`AmbientCapabilities=` rather than the `-u` flag — both
approaches are supported, pick one.

`CAP_NET_ADMIN` alone is not sufficient: the kernel ships
`/dev/ppp` (and the in-tree sstp kmod ships `/dev/sstp`) as
`0600 root:root`, and the VFS DAC check runs *before* capability
checks, so the unprivileged service user is rejected at `open()`.
The Debian package installs
`/lib/udev/rules.d/99-sstp-server.rules` to set both nodes to
`0660 root:sstp-server`; the postinst reloads udev and triggers
a `change` event so the rule applies without a reboot.

If you run the daemon outside the package — e.g. `sudo
./target/release/sstp-server -u $USER` for development — copy
the rule into place by hand:

```bash
sudo install -m 0644 packaging/udev/99-sstp-server.rules \
    /etc/udev/rules.d/99-sstp-server.rules
sudo getent group sstp-server >/dev/null || sudo groupadd --system sstp-server
sudo udevadm control --reload-rules
sudo udevadm trigger --action=change /dev/ppp /dev/sstp
sudo usermod -aG sstp-server "$USER"   # log out / `newgrp` to pick up
```

## Environment variables

Secrets live in env vars, not on the command line (where they'd
leak into `ps` and shell history).

| Variable                      | Purpose                                              |
|-------------------------------|------------------------------------------------------|
| `SSTP_RADIUS_SECRET`          | Shared secret for `--radius` servers. **Required.**  |
| `SSTP_RADIUS_ACCT_SECRET`     | Shared secret for `--acct` servers. Falls back to `SSTP_RADIUS_SECRET`. |
| `SSTP_TLS_KEY_PASSWORD`       | Passphrase for an encrypted TLS private key. Optional. |

The systemd unit reads them from
`/etc/sstp-server/sstp-server.env`. The `postinst` chowns this
file `root:sstp-server` and chmods it `0640` so non-`sstp-server`
users on the host can't read it.

`dotenvy` is loaded at startup for development convenience: a
`.env` file next to the binary, if present, populates the
environment before the systemd-managed env file is parsed. In a
packaged install there is no `.env`, so this is a no-op.

## RADIUS interface

`sstp-server` is RADIUS-only — there is no local user database,
no `htpasswd`, no static config. Every authentication and every
session policy decision goes through RADIUS.

### Access-Request (daemon → RADIUS)

Every PPP authentication produces one RADIUS round trip. The
attributes sent on every request, regardless of method:

| Attribute                | RFC          | Value                                              |
|--------------------------|--------------|----------------------------------------------------|
| `User-Name` (1)          | RFC 2865     | Peer-ID from PAP / CHAP / MS-CHAPv2.               |
| `Service-Type` (6)       | RFC 2865     | `Framed-User` (2).                                 |
| `Framed-Protocol` (7)    | RFC 2865     | `PPP` (1).                                         |
| `NAS-IP-Address` (4)     | RFC 2865     | Local IPv4 the listener accepted on, when known.   |
| `NAS-Port-Type` (61)     | RFC 2865     | `Virtual` (5) — conventional for L2 tunnels.       |
| `NAS-Identifier` (32)    | RFC 2865     | Hostname, or `--nas-identifier`. Omitted if empty. |
| `Calling-Station-Id` (31)| RFC 2865     | Remote peer IP:port of the SSTP TCP connection.    |
| `Called-Station-Id` (30) | RFC 2865     | Local IP:port the client connected to.             |
| `Connect-Info` (77)      | RFC 2869     | `SSTP/<TLS-version>/<cipher>` (e.g. `SSTP/TLS 1.3/AES-256-GCM`). |

Plus method-specific attributes:

- **PAP** → `User-Password` (2), encrypted per RFC 2865 §5.2.
- **CHAP** → `CHAP-Password` (3) + `CHAP-Challenge` (60) per
  RFC 2865 §5.3 / §5.40.
- **MS-CHAPv2** → `MS-CHAP-Challenge` (VSA 311.11) +
  `MS-CHAP2-Response` (VSA 311.25). The RADIUS server validates
  the response and returns MPPE keys; see below.

### Access-Accept (RADIUS → daemon)

Attributes consumed from a successful authentication, in
priority order:

#### Required

| Attribute               | RFC               | Effect                                          |
|-------------------------|-------------------|-------------------------------------------------|
| `Framed-IP-Address` (8) | RFC 2865 §5.8     | Peer-side IPv4 for the `pppN` netdev. **Required** — sessions are rejected if absent. |

#### Optional networking

| Attribute                              | RFC               | Effect                                    |
|----------------------------------------|-------------------|-------------------------------------------|
| `Framed-IP-Netmask` (9)                | RFC 2865 §5.9     | Currently informational; netdev is P2P.   |
| `Framed-MTU` (12)                      | RFC 2865 §5.12    | MTU on the `pppN` netdev; clamped to 1500.|
| `Framed-Route` (22)                    | RFC 2865 §5.22    | Pushed as `RTM_NEWROUTE` to the kernel. Repeatable. |
| `MS-Primary-DNS-Server` (VSA 311.28)   | RFC 2548          | Negotiated to the peer via IPCP.          |
| `MS-Secondary-DNS-Server` (VSA 311.29) | RFC 2548          | Negotiated to the peer via IPCP.          |
| `MS-Primary-NBNS-Server` (VSA 311.30)  | RFC 2548          | Negotiated to the peer via IPCP.          |
| `MS-Secondary-NBNS-Server` (VSA 311.31)| RFC 2548          | Negotiated to the peer via IPCP.          |

#### Session policy

| Attribute                       | RFC                       | Effect                                                                |
|---------------------------------|---------------------------|-----------------------------------------------------------------------|
| `Session-Timeout` (27)          | RFC 2865 §5.27            | Hard session deadline; daemon tears down with `Session-Timeout` cause.|
| `Idle-Timeout` (28)             | RFC 2865 §5.28            | Reset on any byte movement; tears down on inactivity.                  |
| `Acct-Interim-Interval` (85)    | RFC 2869 §5.16            | Interim accounting cadence. Floored at 30 s per RFC guidance.         |
| `Class` (25)                    | RFC 2865 §5.25            | Opaque blob echoed verbatim into Accounting-Request.                   |
| `Reply-Message` (18)            | RFC 2865 §5.18            | Logged on the (rare) attached-to-Accept case.                         |

#### MS-CHAPv2 / MPPE

| Attribute                       | RFC                       | Effect                                                                 |
|---------------------------------|---------------------------|------------------------------------------------------------------------|
| `MS-MPPE-Send-Key` (VSA 311.16) | RFC 2548 / RFC 3079       | Decrypted under the request authenticator + shared secret. Feeds the SSTP Crypto Binding HLAK. |
| `MS-MPPE-Recv-Key` (VSA 311.17) | RFC 2548 / RFC 3079       | Same.                                                                  |
| `MS-CHAP2-Success` (VSA 311.26) | RFC 2548 / RFC 2759 §6    | Authenticator-Response spliced verbatim into the PPP CHAP Success.     |

#### MikroTik shaping (vendor-specific)

The daemon honours MikroTik rate-limit attributes (vendor 14988)
when present. See [`src/auth/reply.rs`](../src/auth/reply.rs) for
the exact decode; conventional usage is `Mikrotik-Rate-Limit`
strings of the form `"<rx>k/<tx>k"` etc.

### Access-Reject

`Reply-Message` (18) and / or `MS-CHAP-Error` (VSA 311.2) are
logged and surfaced to the PPP peer. The session ends with
`sstp_auth_reject` incremented and a `warn`-level log line.

### Accounting

If `--acct` is supplied, the session emits the standard RFC 2866
sequence:

- **Acct-Start** when IPCP converges and the peer's IP is
  installed on the netdev.
- **Acct-Interim-Update** every `Acct-Interim-Interval` seconds
  (default 60 s when the RADIUS server doesn't supply one).
  Byte / packet counters are sampled from the kernel netdev via
  `IFLA_STATS64` netlink — i.e. the same numbers you see in
  `ip -s link show pppN`.
- **Acct-Stop** on session teardown, with `Acct-Terminate-Cause`
  mapped from the internal disconnect reason:

  | Internal cause       | `Acct-Terminate-Cause`        |
  |----------------------|-------------------------------|
  | Peer hung up         | `User-Request` (1)            |
  | Carrier lost         | `Lost-Carrier` (2)            |
  | Idle timeout         | `Idle-Timeout` (4)            |
  | Session timeout      | `Session-Timeout` (5)         |
  | `disable session`    | `Admin-Reset` (6)             |
  | Daemon shutdown      | `NAS-Reboot` (7)              |
  | Internal error       | `NAS-Error` (9)               |
  | Service unavailable  | `Service-Unavailable` (15)    |

`Class` from the Access-Accept is echoed verbatim on every
accounting packet so the RADIUS server can correlate sessions
to its own internal record.

### CoA / Disconnect-Request (RADIUS → daemon)

[RFC 5176] (formerly RFC 3576) Disconnect-Request is supported
out of the box: a RADIUS authenticator can tear down a live
session by sending a UDP packet to the daemon (default port
3799) carrying enough identifying attributes
(`Acct-Session-Id`, `User-Name`, `Framed-IP-Address`, or
`NAS-Port`) to pin a single session. The daemon ACKs and tears
the session down with `Acct-Terminate-Cause = Admin-Reset`.

CoA-Request (changing live session policy without
disconnecting) is parsed but currently rejected with
`Error-Cause = Unsupported-Service` — there's no on-the-fly
policy update path yet. Disconnect is the supported pattern.

The CoA listener is configured per-deployment; see the
`auth::coa::PeerSecrets` plumbing in
[`src/auth/coa.rs`](../src/auth/coa.rs) for how peers and
secrets are registered. The default deb package does not enable
CoA — operators who want it must wire it in via a custom
configuration script.

### Reference RADIUS configuration (FreeRADIUS)

Minimal `users` entry that lets `alice` log in with PAP and
gets `10.99.0.42`:

```
alice   Cleartext-Password := "hunter2"
        Service-Type = Framed-User,
        Framed-Protocol = PPP,
        Framed-IP-Address = 10.99.0.42,
        Framed-IP-Netmask = 255.255.255.255,
        MS-Primary-DNS-Server = 1.1.1.1,
        MS-Secondary-DNS-Server = 9.9.9.9,
        Session-Timeout = 86400,
        Idle-Timeout = 600,
        Acct-Interim-Interval = 300
```

Add a `client` stanza in `clients.conf` for the SSTP server's
IP, with the secret matching `SSTP_RADIUS_SECRET`.

For a quick local-loopback test without FreeRADIUS, use the
in-tree dev RADIUS:

```sh
cargo run --example dev-radius -- -l 127.0.0.1:1812 -p 10.99.0.10-10.99.0.250
```

PAP only, in-memory IP pool, sticky per-username assignment.
Default secret `testing123`. See
[`examples/dev-radius.rs`](../examples/dev-radius.rs) for the
flag list.

## Routing peers onto the network

The daemon does *not* manage the routing table for the address
pool itself. It installs only what the per-session RADIUS reply
asks for: a P2P address pair on the per-session `pppN` / `tunN`
netdev (from `Framed-IP-Address`), and any `Framed-Route`
entries the reply carries. Everything beyond that — the route
that tells the host kernel "addresses in `10.99.0.0/24` live on
SSTP" — is an operator-side decision. There are two common
shapes:

### Shape A — per-session host routes (default)

The simplest deployment relies entirely on what the daemon
already does. Each session installs a `/32` peer address on its
own `pppN` (kernel) or `tunN` (TUN fallback) netdev:

```text
$ ip -4 route show
...
10.99.0.42 dev ppp0 proto kernel scope link src 10.255.255.1
10.99.0.57 dev ppp1 proto kernel scope link src 10.255.255.1
```

No additional configuration. Pros: zero operator work,
returning traffic for an offline peer fails fast (no route).
Cons: routes appear and vanish as sessions come and go, which
makes the kernel routing table noisy on busy servers and
complicates IGP redistribution. Recommended for small
deployments and for the dev-radius pool above.

### Shape B — single pool route on a parent interface

Operators with hundreds of concurrent sessions, or who want a
stable IGP advertisement, typically pre-install a single covering
route to the pool on whatever upstream-facing interface owns the
gateway address, then let proxy-ARP / ND or routing protocols
draw traffic in:

```sh
ip route add 10.99.0.0/24 dev eth0
echo 1 > /proc/sys/net/ipv4/conf/eth0/proxy_arp
```

The per-session `/32`s are still installed on the `pppN` /
`tunN` netdevs and remain longest-match, so traffic for live
peers goes through SSTP and traffic for offline peers is
black-holed by the parent route (or, with `proxy_arp`,
ICMP-unreachable'd by the host stack).

Pros: routing-table size is constant, IGP advertisements are
stable, no churn. Cons: requires one piece of out-of-band
configuration per address pool.

### Shape C — `Framed-Route` for off-LAN destinations

When a peer sits in front of its own subnet and you want the
SSTP server to forward toward that subnet, the reply attaches
`Framed-Route` to the Access-Accept. RFC 2865 §5.22 wire format
is `"<network>/<prefix> <gateway> [<metric>]"`; the daemon
parses the entry in [`src/auth/route.rs`](../src/auth/route.rs)
and installs it via
[`RtNetlink::add_framed_route`](../src/kppp/netlink.rs)
(`RTM_NEWROUTE`) right after IPCP converges:

```
alice   Cleartext-Password := "hunter2"
        Framed-IP-Address  = 10.99.0.42,
        Framed-Route       = "192.168.50.0/24 10.99.0.42 1",
        Framed-Route       = "192.168.51.0/24 0.0.0.0 1"
```

Both forms are accepted: an explicit gateway, or `0.0.0.0`
(meaning "via the peer's `Framed-IP-Address`", which is what
most deployments want). The route is scoped to the per-session
netdev, so it disappears automatically with the session.

### Picking a shape

| Situation                                           | Use   |
|-----------------------------------------------------|-------|
| Small deployment, dev-radius, single pool, < 50 sessions | A     |
| Large deployment, BGP / OSPF redistribution, stable RIB | B     |
| Peers route their own LANs on top of the SSTP link  | C (with A or B for the pool itself) |

Shapes A and C combine naturally; A and B do not (B replaces
A's expectation that the pool prefix is unrouted by default).
Operators occasionally want B *plus* the daemon to skip the
per-session `/32`s — that's not currently supported, and the
TUN fallback in particular relies on the `/32` route to know
which session a host-stack-egress packet belongs to.

## Control socket

A JSON-RPC 2.0 socket exposes runtime stats and administrative
commands over a Unix-domain stream. Default path
`/run/sstp-server/sstp-server.sock` (under the systemd
`RuntimeDirectory`); override with `--control-socket` or disable
with `--no-control-socket`.

Permissions on the default path are `0660`,
`root:sstp-server`, so any user in the `sstp-server` group
can talk to it. Frames are NUL-delimited (a single `\0` byte
after each complete JSON object). Drive it with `socat` or
`nc`:

```sh
# show.info — daemon version, uptime, thread counts, active sessions
printf '{"jsonrpc":"2.0","method":"show.info","id":1}\0' \
    | sudo socat - UNIX-CONNECT:/run/sstp-server/sstp-server.sock

# show.stat — all metrics as a JSON object
printf '{"jsonrpc":"2.0","method":"show.stat","id":1}\0' \
    | sudo socat - UNIX-CONNECT:/run/sstp-server/sstp-server.sock
```

The interactive REPL (`sstp-server-cli`) accepts the same
text commands the old line-oriented protocol used, but
translates them to JSON-RPC internally:

```sh
sstp-server-cli                           # interactive REPL
sstp-server-cli -c "show info"            # one-shot
```

### Methods

| Method               | Params                | Returns                              |
|----------------------|-----------------------|--------------------------------------|
| `show.info`          | —                     | `{version, uptime_seconds, io_threads, auth_threads, active_sessions}` |
| `show.stat`          | —                     | `{sstp_connections_accepted: N, …}`  |
| `show.session.list`  | —                     | `[{id, peer, user, ip, uptime, backend, cipher}, …]` |
| `show.session.get`   | `{id: u64}`           | Full session detail object           |
| `session.disable`    | `{id: u64}`           | `{ok: bool, message: str}`          |
| `session.rekey`      | `{id: u64, request_peer?: bool}` | `{ok: bool, message: str}` |
| `shutdown`           | —                     | `{message: "shutting down"}`         |

All methods are JSON-RPC 2.0 notifications when `id` is omitted
(no response is sent). Batch requests (array of request objects)
are supported.

`show.stat` returns every metric as a flat JSON object keyed by
the `sstp_*` metric name:

```json
{
  "sstp_connections_accepted": 41,
  "sstp_connections_active": 7,
  "sstp_handshake_failures": 2,
  "sstp_auth_accept": 39,
  "sstp_auth_reject": 2,
  "sstp_session_teardown_clean": 28,
  "sstp_session_teardown_admin": 3,
  "sstp_session_teardown_coa": 1,
  "sstp_session_teardown_shutdown": 0,
  "sstp_session_panics": 0,
  "sstp_crypto_binding_failures": 0,
  "sstp_log_lines_dropped": 0
}
```

There is **no** Prometheus exposition format and no HTTP
endpoint built into the daemon. To expose these to Prometheus,
front the control socket with a tiny scraper sidecar (a
30-line shell or Python script calling `show.stat` and
emitting `text/plain` is enough).

`show.session.list` returns an array of per-session summaries:

```json
[
  {
    "id": "1234",
    "peer": "203.0.113.4:51022",
    "user": "alice",
    "ip": "10.99.0.42",
    "uptime": "5m12s",
    "backend": "kmod",
    "cipher": "TLS_AES_256_GCM_SHA384"
  }
]
```

The `id` field in each session object is what `session.disable`,
`session.rekey`, and `show.session.get` accept.

`shutdown` is equivalent to `systemctl stop sstp-server`: it
stops accepting new connections, broadcasts a graceful
disconnect to every active session, waits up to 10 seconds for
them to drain, and exits.

## Logging

Default level is `warn`. `-v` / `-vv` / `-vvv` raise it through
`info` / `debug` / `trace`. Even at `trace` the data path
remains silent — per-packet logging is reserved for `tcpdump` /
eBPF, not the daemon.

What each level covers:

- **`warn`** — protocol violations the daemon tolerates,
  RADIUS retries, fallback events.
- **`info`** — per-session lifecycle: TCP accept, TLS
  handshake outcome, RADIUS Access-Accept / Reject, kernel
  unit attach, teardown reason.
- **`debug`** — control-plane state transitions: LCP
  negotiation, IPCP option exchange, SSTP state machine
  steps, per-attribute RADIUS request/response trace
  (secrets are redacted to `<len=N>`).
- **`trace`** — per-frame control plane. Useful for
  reproducing interop bugs against captured Windows traces;
  do not enable in production.

`--log-format auto` emits human-readable text on a TTY and JSON
otherwise (so journald / Loki / a log shipper get structured
fields automatically). Force one or the other with
`--log-format text` / `--log-format json`.

`--log-file` writes to a file via the same non-blocking
appender. The file is opened once at startup with `O_APPEND`
and never reopened, so rotate it with `logrotate`'s
`copytruncate` (a `SIGHUP`-on-rotate scheme would race the
appender thread). The Debian package ships exactly that:
[`/etc/logrotate.d/sstp-server`](../packaging/sstp-server.logrotate)
rotates `/var/log/sstp-server/sstp-server.log` daily with
14 days of compressed history. The log queue is bounded; if a
slow log consumer fills it, lines are dropped and the counter
`sstp_log_lines_dropped` ticks up — the daemon will never block
the data path on a logging hiccup.

**Default in the Debian package.** The shipped
`/etc/sstp-server/sstp-server.env` includes
`--log-file /var/log/sstp-server/sstp-server.log` in `OPTS`,
so a fresh install logs JSON to that file out of the box.
`/var/log/sstp-server` is created by systemd
(`LogsDirectory=sstp-server`, mode `0750`, owned by the
`sstp-server` user). Drop the `--log-file` flag from `OPTS` to
revert to stderr → journald.

## Running in containers

`sstp-server` is fine to run inside containers, including
unprivileged ones, as long as the kernel module's container-
compatibility requirements are met. The kmod README has the
authoritative checklist; the short version:

- Load `sstp.ko` and `ppp_generic` on the **host**, not in the
  container. The DKMS package handles the kmod side.
- Pass the device nodes through:
  `--device=/dev/sstp --device=/dev/ppp --device=/dev/net/tun`.
- Grant capabilities, not `--privileged`:
  `--cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE`.
- Enable forwarding:
  `--sysctl net.ipv4.ip_forward=1`.

See [`../kmod/README.md`](../kmod/README.md) §"Running in
containers" for the full recipe and the rootless / userns
notes.

## Troubleshooting

### Clients can't connect at all

1. **TCP/443 reachable?** `curl -v https://your.server.example/`
   should produce an SSTP-style `400 Bad Request` (the daemon
   refuses non-SSTP HTTP). If you don't get that far, it's
   firewall / NAT.
2. **Cert trusted?** `openssl s_client -connect your.server:443
   -servername your.server` and inspect the chain. Windows
   clients fail silently on cert validation; the daemon log
   only sees the TLS handshake fail with
   `sstp_handshake_failures` ticking up.
3. **Cipher kTLS-eligible?** If `--data-path kernel` (strict),
   the daemon refuses non-kTLS ciphers. Use `--data-path auto`
   while debugging; kernel-mode mismatch shows up as
   `sstp_handshake_failures`.

### RADIUS is rejecting everything

- Watch with `-vv` and confirm you see the RADIUS round-trip
  log line (`debug` level). Check the `User-Name` /
  `Calling-Station-Id` look right.
- Confirm `SSTP_RADIUS_SECRET` matches the `client` stanza on
  the RADIUS side. A mismatched secret on FreeRADIUS produces
  `Received Access-Request packet from <ip> with invalid
  Message-Authenticator!` in `radiusd -X`.
- Confirm the user's reply contains `Framed-IP-Address`. Without
  it the daemon logs `auth failed: missing Framed-IP-Address`
  and increments `sstp_auth_reject`. This is a frequent
  misconfiguration on RADIUS servers that only set a pool name
  expecting the NAS to allocate.

### `pppN` doesn't appear

- `--data-path kernel` requires `/dev/sstp` to exist. `lsmod |
  grep sstp` and `ls /dev/sstp`. If the kmod fails to attach,
  the daemon logs `kmod attach failed: …` and (under
  `auto`) falls back to a TUN device.
- `/dev/ppp` requires `ppp_generic`. Most distros ship it
  built-in; if it's a module, `modprobe ppp_generic`.
- Privilege drop with `-u` strips capabilities by default; the
  daemon retains `CAP_NET_ADMIN` deliberately. If you removed
  it via systemd `CapabilityBoundingSet=` or manual setuid,
  `PPPIOCNEWUNIT` will return `EPERM`.

### Throughput is bad

- `show stat` first. If `sstp_session_teardown_clean` is
  growing fast and connections are short, the bottleneck is
  setup, not steady state.
- Confirm the kernel backend is in use: a session log line
  contains `data-path: kernel` at attach time. If you see
  `tun fallback`, you're paying the per-packet userspace
  round-trip — install `sstp-server-dkms` and reload.
- `ip -s link show pppN` shows kernel-side counters. If
  packets-per-second is high but bytes-per-second is low,
  you're CPU-bound on small packets — try
  `--no-mss-clamp` only if you know the path's PMTU.

### Crypto binding failures

`sstp_crypto_binding_failures` should always be zero in
production. A non-zero value means a client computed the
[MS-SSTP] §3.2.5.2 HMAC over a key that doesn't match what the
daemon derived. The two common causes:

1. The RADIUS server's `MS-MPPE-Send-Key` /
   `MS-MPPE-Recv-Key` were derived against a different
   challenge than the one the client used (i.e. the RADIUS
   server is buggy or interposing on MS-CHAPv2).
2. The TLS exporter ran against a different cipher than the
   client's, which would mean the daemon and client disagree
   on the negotiated TLS suite — in practice this only happens
   with broken middleboxes.

Capture a `tcpdump` of the SSTP TCP stream (the TLS contents
won't help directly, but the framing will), enable `-vvv`, and
file a bug.

### Stale `sstp_mss_*` nftables tables after a crash

TCP MSS clamping uses a PID-scoped `nf_tables` table named
`sstp_mss_<PID>`. It holds one chain plus one named set per
distinct MSS value; each session only adds its netdev name to
the appropriate set (and removes it on teardown). The daemon
deletes the table on a clean exit. SIGKILL and process-abort
bypass that cleanup — the kernel has no way to know the
userspace owner is gone, so the table lingers until something
deletes it.

The systemd unit sweeps stragglers in `ExecStartPre=` before
each start, so a `systemctl restart` after a crash is enough.
For non-systemd deployments (containers, manual runs), do the
same thing by hand:

```sh
nft list tables ip \
    | grep -oE 'sstp_mss[A-Za-z0-9_]*' \
    | while read t; do nft delete table ip "$t"; done
```

This is safe to run any time the daemon is *not* live; running
it while the daemon is up will tear down clamping for active
sessions until they reconnect.

## Upgrading

The Debian package upgrade flow is the standard `apt install`.
The systemd unit gets `Restart=on-failure`, but during a
package upgrade the unit is restarted explicitly by `dh_installsystemd`'s
`postinst` snippet. Active sessions disconnect; clients
reconnect within a few seconds.

For zero-downtime upgrades, run two instances behind a
TCP-level load balancer (HAProxy, nftables `dnat`) and drain
one at a time via `shutdown` on the control socket.

## See also

- [data-path.md](data-path.md) — how IP packets actually move
  through the daemon and the kernel module.
- [../README.md](../README.md) — project overview and quick start.
- [../kmod/README.md](../kmod/README.md) — kernel module build,
  load, container guidance.
- [../MS-SSTP-spec.md](../MS-SSTP-spec.md) — the wire format,
  rendered from Microsoft's Open Specification PDF.
- [RFC 2865] / [RFC 2866] — RADIUS auth + accounting.
- [RFC 2548] — Microsoft VSAs (MS-MPPE-*, MS-CHAP2-*).
- [RFC 5176] — Dynamic Authorization (CoA / Disconnect-Request).

[RFC 1994]: https://datatracker.ietf.org/doc/html/rfc1994
[RFC 2548]: https://datatracker.ietf.org/doc/html/rfc2548
[RFC 2759]: https://datatracker.ietf.org/doc/html/rfc2759
[RFC 2865]: https://datatracker.ietf.org/doc/html/rfc2865
[RFC 2866]: https://datatracker.ietf.org/doc/html/rfc2866
[RFC 2869]: https://datatracker.ietf.org/doc/html/rfc2869
[RFC 5176]: https://datatracker.ietf.org/doc/html/rfc5176
