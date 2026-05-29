# sstp.ko — Linux kernel module (v0.1 DRAFT)

In-kernel SSTP channel driver. Pairs with the userspace
`sstp-server` daemon: once userspace finishes the TLS handshake,
SSTP negotiation, PPP LCP/auth/IPCP, and installs kTLS RX+TX
crypto on the TCP socket, it hands the socket and a PPP unit
number to this module via `ioctl(SSTP_IOC_ATTACH)`. The module
then registers a `ppp_channel` and (eventually) runs the
steady-state SSTP demux entirely in kernel context.

**v0.1 status.** The module compiles cleanly and exercises the
full attach/detach lifecycle plus the per-frame paths in both
directions:

- **RX**: `sk_data_ready` hook → workqueue → `kernel_recvmsg` →
  [MS-SSTP] §2.2.3 reassembly (max 4095 B frames straddling TLS
  records) → `ppp_input()` per data frame. Malformed framing
  surfaces as a `SSTP_EVT_PROTOCOL_ERROR` event on `session_fd`
  and tears the session down.
- **TX**: `ppp_channel_ops.start_xmit` prepends the 4-byte SSTP
  data-packet header and `kernel_sendmsg`s on the kTLS socket;
  short writes / hard errors abort the session.
- **Userspace binding**: `SSTP_IOC_GET_CHAN_INDEX` returns the
  registered channel id so userspace can `PPPIOCATTCHAN` +
  `PPPIOCCONNECT` against its own `/dev/ppp` handle.

Still TODO before v0.1 ships:

- `sk_write_space` hook + `ppp_output_wakeup` so a full socket
  buffer pauses ppp_generic instead of dropping the frame.
- Control-packet (`C=1`) forwarding to userspace so the SSTP
  hello timer can stay in userspace (today they are counted and
  dropped).
- TLS 1.3 `KeyUpdate` detection → `SSTP_EVT_TLS_REKEY_NEEDED`.

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

## Testing

A self-contained userspace lifecycle test lives under
[kmod/tests/](tests/). It exercises:

- `/dev/sstp` open + ioctl dispatch.
- Negative `SSTP_IOC_ATTACH` paths (bad ABI major, reserved-nonzero,
  negative fd, non-socket fd, plain TCP without kTLS → `-EOPNOTSUPP`).
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

## Next steps

In rough order:

1. **TX backpressure**: install `sk_write_space` on the TCP socket
   so `-EAGAIN` from `kernel_sendmsg` returns 0 from start_xmit
   (telling ppp_generic to queue), then `ppp_output_wakeup` when
   space is available.
2. **Control-packet forwarding**: post-handoff Echo Request /
   Response should surface to userspace via a new
   `SSTP_EVT_CONTROL_PACKET` event with the payload available via
   a read of the session_fd, so the hello timer stays where the
   state machine lives.
3. **TLS rekey handling**: detect TLS 1.3 KeyUpdate records,
   emit `SSTP_EVT_TLS_REKEY_NEEDED`, suspend the data path until
   userspace reinstalls crypto info via `setsockopt(SOL_TLS, ...)`.
4. **Userspace integration**: the Rust `kppp` module needs an
   `attach()` helper that wraps `SSTP_IOC_ATTACH` +
   `SSTP_IOC_GET_CHAN_INDEX` + `PPPIOCATTCHAN` + `PPPIOCCONNECT`
   so a session can flip from userspace to kernel data path once
   IPCP converges.
