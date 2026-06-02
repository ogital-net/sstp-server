# sstp.ko — Linux kernel module (v0.3)

In-kernel SSTP channel driver. Pairs with the userspace
`sstp-server` daemon: once userspace finishes the TLS handshake,
SSTP negotiation, PPP LCP/auth/IPCP, and installs kTLS RX+TX
crypto on the TCP socket, it hands the socket to this module via
`ioctl(SSTP_IOC_ATTACH)`. The module registers a `ppp_channel`
and runs the steady-state SSTP demux entirely in kernel context.

**v0.3 status.** ABI frozen for the v0.x series. v0.3 extends
the v0.2 surface additively:

- `SSTP_IOC_SEND_CONTROL` — emit a C=1 SSTP control frame
  through the kmod's TX path. Always non-blocking; backpressure
  is reported as `-EAGAIN` and userspace waits on
  `EPOLLOUT | EPOLLWRNORM` from `poll(session_fd)` before
  retrying. Lets userspace close its writable dup of the TCP fd
  after attach.
- `SSTP_IOC_REKEY_TX` / `SSTP_IOC_REKEY_RX` — **reserved; not
  planned for the v0.x series.** v0.3 returns `-ENOSYS`. Any
  non-application-data TLS record post-attach (`KeyUpdate`,
  unexpected `NewSessionTicket`, alerts) is treated as fatal:
  the kmod emits `SSTP_EVT_TLS_REKEY_NEEDED` and closes the
  session. This matches HAProxy's AWS-LC + kTLS posture
  ([`src/ssl_sock.c`][haproxy-ssl] — TLS 1.3 `KeyUpdate` post-
  handshake aborts the connection; only `NewSessionTicket` and
  `close_notify` are tolerated, and we suppress server-side NSTs
  with `SSL_CTX_set_num_tickets(0) + SSL_OP_NO_TICKET`). The
  motivation to revisit is long-running tunnels approaching the
  AES-GCM per-key record-count ceiling (~2^24.5 records); SSTP
  sessions are days-long where HAProxy's are seconds, so this
  bound matters more for us. Until then, callers should treat
  these ioctl numbers as allocated but unimplementable.

[haproxy-ssl]: https://git.haproxy.org/?p=haproxy.git;a=blob;f=src/ssl_sock.c
- `struct sstp_stats` gains `ctrl_frames_rx`, `ctrl_frames_tx`,
  and `tx_send_errors`. The struct is strictly extended; older
  callers that read `sizeof(v0.2 sstp_stats)` see the same prefix. The module
implements the full attach/detach lifecycle plus the per-frame
paths in both directions:

- **RX**: `sk_data_ready` hook → workqueue → `kernel_recvmsg` →
  [MS-SSTP] §2.2.3 reassembly (max 4095 B frames straddling TLS
  records) → `ppp_input()` per data frame. Malformed framing
  surfaces as a `SSTP_EVT_PROTOCOL_ERROR` event on `session_fd`
  and tears the session down.
- **TX**: `ppp_channel_ops.start_xmit` prepends the 4-byte SSTP
  data-packet header and `kernel_sendmsg`s on the kTLS socket;
  short writes / hard errors abort the session, and a full
  socket buffer parks the channel until `sk_write_space` triggers
  `ppp_output_wakeup()`.
- **Control plane**: `C=1` SSTP frames are demuxed off the data
  path, queued, and surfaced to userspace via
  `SSTP_EVT_CONTROL_PACKET` + `SSTP_IOC_RECV_CONTROL`. TLS 1.3
  `KeyUpdate` / `NewSessionTicket` records raise
  `SSTP_EVT_TLS_REKEY_NEEDED`.
- **Userspace binding**: the kmod registers the channel only.
  Userspace fetches the channel index via
  `SSTP_IOC_GET_CHAN_INDEX` and binds it to its already-created
  PPP unit using the standard `ppp_generic` ABI
  (`PPPIOCATTCHAN` + `PPPIOCCONNECT` on a fresh `/dev/ppp` fd).
  `ppp_connect_channel()` is unexported in mainline
  `ppp_generic`, so doing the bind from userspace is the
  pragmatic choice.

Verified end-to-end on Linux 6.8 by
[`tests/e2e.rs`](../tests/e2e.rs) `sstpc_pap_login`: PAP login
over TLS 1.3 + AES-GCM, ICMP echo across the tunnel, server-side
`pppN` `rx_bytes` grows by the expected payload count.

## Files

| File              | Role                                                   |
|-------------------|--------------------------------------------------------|
| `sstp_main.c`     | module init/exit, `/dev/sstp` misc dev, top-level ioctl |
| `sstp_attach.c`   | `SSTP_IOC_ATTACH`: validate, register channel, mint fd |
| `sstp_event.c`    | session_fd file_operations: poll/read/ioctl/release    |
| `sstp_chan.c`     | `struct ppp_channel_ops` (TX path stub)                |
| `sstp_demux.c`    | receive workqueue + shutdown (RX path stub)            |
| `sstp_internal.h` | module-private types and prototypes                    |
| `include/uapi/linux/sstp.h` | symlink to `../../../../kernel-abi/sstp.h`    |

The UAPI header is the same file consumed by userspace
(`crate::kppp` and friends in the Rust tree), kept under
`kernel-abi/` at the repository root and pulled into the kmod
build via a `-I$(src)/include` symlink so out-of-tree builds
don't need it installed system-wide.

## Build

Requires kernel headers for a tree with `CONFIG_PPP=m` (or `=y`).
The cloud-flavour Debian kernels do not enable `CONFIG_PPP`; use
the generic flavour.

```sh
# Pick a kernel tree to build against. /lib/modules/$(uname -r)/build
# is the default for "build for the running kernel".
make -C kmod KDIR=/lib/modules/$(uname -r)/build

# Out-of-tree-against-a-different-kernel example (CI / cross builds):
make -C kmod KDIR=/lib/modules/6.12.86+deb13-arm64/build
```

The artifact lands at `kmod/sstp.ko`. `modinfo kmod/sstp.ko`
should report `depends: ppp_generic` and `alias: devname:sstp`.

## Loading

```sh
sudo modprobe tls               # kTLS ULP; the kmod rejects attach without it
sudo insmod kmod/sstp.ko        # /dev/sstp appears with mode 0600, root-only
sudo rmmod sstp                 # safe even with attached sessions:
                                # rmmod waits for refs to drop
```

`ppp_generic` is built in on most distro kernels (`CONFIG_PPP=y` on
Ubuntu); when it is a module (`=m`) modprobe it first.

## Running in containers

The kmod is namespace-aware: a daemon running inside a container
with its own network namespace gets a `pppN` netdev in *that*
netns, the channel is registered against the container's net_ns
(via `ppp_register_channel()` → `current->nsproxy->net_ns`), and
the steady-state demux carries the socket's netns implicitly
through `kernel_recvmsg` / `kernel_sendmsg`. There is no host
leakage.

Capability check on `SSTP_IOC_ATTACH` is `ns_capable(
current_user_ns(), CAP_NET_ADMIN)` — i.e. the cap is checked
against the caller's user namespace, so user-namespaced root
(rootless Podman, Docker `--userns-remap`, k8s
`securityContext.runAsNonRoot`) works as long as the container
holds CAP_NET_ADMIN over its own ns.

**The module must be loaded on the host, not inside the
container.** Containers cannot (and should not) call
`init_module()`; `modprobe sstp` belongs in the host's boot
sequence. The DKMS package's `AUTOINSTALL=yes` handles this
automatically once installed.

The container then needs:

1. The two device nodes exposed (and `/dev/net/tun` if you want
   the TUN fallback path to work too):

   ```sh
   --device=/dev/sstp --device=/dev/ppp --device=/dev/net/tun
   ```

2. Two capabilities (no `--privileged`):

   ```sh
   --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE
   ```

3. IP forwarding enabled in the container's netns:

   ```sh
   --sysctl net.ipv4.ip_forward=1
   ```

Concrete Docker / Podman invocation:

```sh
docker run --rm \
    --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
    --device=/dev/sstp --device=/dev/ppp --device=/dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    -p 443:443 \
    sstp-server:0.1.0
```

For Kubernetes, the equivalent pod spec is
`securityContext.capabilities.add: [NET_ADMIN, NET_BIND_SERVICE]`
plus a hostPath mount for each `/dev/{sstp,ppp,net/tun}` (or a
device plugin if your cluster uses one).

If `/dev/sstp`'s default `0600` perms are wrong for your
container's uid, load the kmod with `mode=0660` and use a host
udev rule to set the group:

```
# /etc/udev/rules.d/60-sstp.rules
KERNEL=="sstp", MODE="0660", GROUP="sstp"
```

## Testing

A self-contained userspace lifecycle test lives under
[kmod/tests/](tests/). It exercises:

- `/dev/sstp` open + ioctl dispatch.
- Negative `SSTP_IOC_ATTACH` paths (bad ABI major, negative fd,
  non-socket fd, plain TCP without kTLS → `-EOPNOTSUPP`).
- The happy path: loopback TCP with OpenSSL TLS 1.2 + AES-GCM and
  `SSL_OP_ENABLE_KTLS` so the kernel sees a kTLS-equipped socket;
  `ATTACH` succeeds, `GETSTATS` returns zeros, `poll()` is quiet,
  `DETACH` flips the session into closing and `poll()` then reports
  `POLLHUP`, `close(session_fd)` triggers the refcounted teardown.

```sh
cd kmod/tests
make run        # builds kmod (if needed), loads it, runs test_sstp,
                # prints last dmesg, attempts rmmod
```

Requires `libssl-dev` (OpenSSL 3.x) and passwordless `sudo` (for
`insmod` / `rmmod` / running as `CAP_NET_ADMIN`).

## Roadmap

Landed in v0.1.x → v0.2:

- TX backpressure via `sk_write_space` + `ppp_output_wakeup`
  ([`sstp_demux.c`](sstp_demux.c), [`sstp_chan.c`](sstp_chan.c)).
- Control-packet (`C=1`) demux + queue + `SSTP_EVT_CONTROL_PACKET`
  event + `SSTP_IOC_RECV_CONTROL` ioctl
  ([`sstp_demux.c`](sstp_demux.c), [`sstp_event.c`](sstp_event.c)).
- TLS 1.3 KeyUpdate / NewSessionTicket detection via
  `TLS_GET_RECORD_TYPE` cmsg on `kernel_recvmsg`, surfacing
  `SSTP_EVT_TLS_REKEY_NEEDED` ([`sstp_demux.c`](sstp_demux.c)).
- Userspace `kppp` integration: `SSTP_IOC_ATTACH` +
  channel↔unit bind via `PPPIOCATTCHAN`/`PPPIOCCONNECT` on a
  separate `/dev/ppp` fd held for the session lifetime.
- kTLS install in `crate::crypto::tls` so attach succeeds against
  TLS 1.2 / 1.3 with AES-GCM or ChaCha20-Poly1305.
- ABI freeze for v0.x at minor 2: `struct sstp_attach` shrunk
  to 16 bytes (no `ppp_unit` / `flags` / `reserved`);
  `struct sstp_detach` removed (`SSTP_IOC_DETACH` is now `_IO`);
  stats counters migrated to `atomic64_t` and gained
  `evt_dropped`.

Follow-on work (v0.3+):

- Lockdep / KASAN soak tests under stress.
- Performance numbers vs. `accel-ppp`.
- Upstream allocation of the ioctl type byte
  (`SSTP_IOC_MAGIC = 'S'` is provisional).
