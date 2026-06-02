# sstp-server

A high-performance, Linux-only [SSTP] (Secure Socket Tunneling
Protocol) server in Rust. Terminates SSTP/TLS from Windows
clients, runs PPP, authenticates against RADIUS, and forwards IP
through the Linux kernel.

[SSTP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/

## What it is

- **Server only.** Accepts SSTP clients on TCP/443, terminates
  TLS, negotiates PPP, hands the resulting interface to the
  kernel for IP forwarding. No client mode, no cross-platform
  support.
- **Performance-first.** Per-core `SO_REUSEPORT` listeners, no
  global locks on the steady-state packet path, optional
  in-kernel data plane (kTLS + a small kernel module) that keeps
  bulk traffic out of userspace entirely once the session is
  established.
- **RADIUS-driven.** Authentication (PAP / CHAP / MS-CHAPv2),
  IP address assignment, routes, DNS, session policy, and
  accounting all come from a RADIUS server — there are no local
  user databases, no in-process address pools, and no config
  files. CLI flags + env vars only.
- **Spec-faithful.** Wire format and state machine follow
  [MS-SSTP] as rendered in [MS-SSTP-spec.md](MS-SSTP-spec.md).

[MS-SSTP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/

## Status

**v0.1 — early release.** Interop-tested against the Windows
built-in SSTP client and `sstp-client` (`sstpc`). PAP /
MS-CHAPv2 / CHAP authentication. IPv4 (IPCP) only — IPv6CP is
on the roadmap. The kernel data path is verified end-to-end on
Linux 6.8 (Ubuntu 24.04) and 6.12 (Debian 13); kTLS-incompatible
TLS ciphers and kernels without `CONFIG_PPP` fall back
transparently to a userspace TUN data path.

## Install

### From the Debian package (recommended)

The release page on GitHub publishes `.deb` files for Debian
12 (bookworm), Debian 13 (trixie), and Ubuntu 24.04 (noble).
Two binary packages:

- `sstp-server` — daemon, systemd unit, default config, logrotate
  snippet, certbot deploy hook.
- `sstp-server-dkms` — out-of-tree kernel module shipped as
  DKMS sources, rebuilt automatically against the running
  kernel.

```sh
sudo apt install ./sstp-server_<version>~debian-13.deb \
                 ./sstp-server-dkms_<version>~debian-13.deb
sudo $EDITOR /etc/sstp-server/sstp-server.env
sudo systemctl enable --now sstp-server
```

The DKMS package builds the kernel module on install. If the
module doesn't load (e.g. the kernel lacks `CONFIG_PPP=m`), the
daemon transparently falls back to the userspace TUN data path
— installation still succeeds, just with reduced throughput.

### From source

```sh
# Build deps: rustc >= 1.85, cargo, cmake, clang, libclang-dev,
# pkg-config, perl. Linux kernel headers (any reasonably modern
# tree with CONFIG_PPP and kTLS support — verified on 6.8+) for
# the in-kernel data path.
git clone https://github.com/ogital-net/sstp-server
cd sstp-server
make            # builds the daemon
sudo make install
# Optional: build + install the kernel module against the
# running kernel (skips the DKMS layer).
make kmod
sudo make kmod-install
sudo depmod -a
```

`make install` lays the daemon out under `/usr/sbin`,
the systemd unit under `/usr/lib/systemd/system`, the default
config under `/etc/sstp-server/`, and the logrotate snippet
under `/etc/logrotate.d/`. Override layout with the standard
`DESTDIR` / `PREFIX` / `SYSCONFDIR` make variables.

## Quick start

Minimal viable deployment, assuming you already have a TLS cert
and a RADIUS server reachable from the host:

```sh
SSTP_RADIUS_SECRET=your-shared-secret \
sstp-server \
    --listen [::]:443 \
    --cert /etc/sstp-server/server.crt \
    --key  /etc/sstp-server/server.key \
    --radius 10.0.0.5:1812 \
    --acct   10.0.0.5:1813 \
    --local-ip 10.255.255.1 \
    -v
```

The RADIUS server must return `Framed-IP-Address` for accepted
users; the daemon does not synthesize addresses. Required and
optional Access-Accept attributes — including
`Framed-IP-Netmask`, `Framed-Route`, `Framed-MTU`,
`MS-Primary-DNS-Server`, `Session-Timeout`, `Idle-Timeout`,
`Acct-Interim-Interval`, `Class`, `MS-MPPE-{Send,Recv}-Key`, and
the MikroTik shaping VSAs — are documented in the
[admin guide](docs/admin-guide.md#radius-interface).

For Let's Encrypt + automatic certificate renewal without
dropping sessions, see the
[TLS certificates](docs/admin-guide.md#tls-certificates)
section: certbot's deploy hook is shipped with the package.

## Documentation

- **[docs/admin-guide.md](docs/admin-guide.md)** — operator
  guide. Installation, CLI reference, environment variables,
  full RADIUS attribute coverage, control socket, logging,
  troubleshooting, container deployment.
- **[docs/data-path.md](docs/data-path.md)** — how a single IP
  packet moves through the daemon and the kernel module; useful
  if you're picking up the codebase or debugging throughput.
- **[kmod/README.md](kmod/README.md)** — kernel module build,
  load, and container-runtime guidance.
- **[MS-SSTP-spec.md](MS-SSTP-spec.md)** — Microsoft's SSTP
  Open Specification, rendered to markdown.

## Runtime requirements

- A reasonably modern Linux kernel for the in-kernel data path:
  kTLS (`CONFIG_TLS=m`) and PPP (`CONFIG_PPP=m`). Verified on
  6.8 (Ubuntu 24.04) and 6.12 (Debian 13); older 6.x kernels
  with both options should work but are not regularly tested.
  Kernels without those options, or TLS ciphers kTLS doesn't
  cover, fall back to the userspace TUN data path at lower
  throughput.
- `CAP_NET_BIND_SERVICE` (TCP/443) and `CAP_NET_ADMIN` (per
  session, for `/dev/ppp` and netlink). The shipped systemd
  unit uses `AmbientCapabilities=` so the daemon does not run
  as root.
- A RADIUS server (FreeRADIUS, NPS, accel-ppp's built-in
  authenticator, or the in-tree
  [`examples/dev-radius.rs`](examples/dev-radius.rs) for
  testing).

## Project status and contributing

This is a v0.1 release. Bug reports, interop traces from clients
we haven't tested against, and PRs welcome. See
[docs/data-path.md](docs/data-path.md) for an internals overview
before sending changes that touch the data path.

## License

BSD-2-Clause. The kernel module under [kmod/](kmod/) is
dual-licensed `BSD-2-Clause OR GPL-2.0` and declares
`MODULE_LICENSE("Dual BSD/GPL")` so it loads as a
GPL-compatible module while remaining redistributable under
BSD-2-Clause alongside the rest of the project.
See [debian/copyright](debian/copyright) for the full breakdown.
