# sstp.ko — Linux kernel module (v0.1 DRAFT)

In-kernel SSTP channel driver. Pairs with the userspace
`sstp-server` daemon: once userspace finishes the TLS handshake,
SSTP negotiation, PPP LCP/auth/IPCP, and installs kTLS RX+TX
crypto on the TCP socket, it hands the socket and a PPP unit
number to this module via `ioctl(SSTP_IOC_ATTACH)`. The module
then registers a `ppp_channel` and (eventually) runs the
steady-state SSTP demux entirely in kernel context.

**v0.1 status.** The module compiles cleanly and exercises the
full attach/detach lifecycle: `/dev/sstp` misc node, kTLS
validation on the supplied TCP fd, `ppp_register_channel`,
anon-inode session fd with `poll/read/ioctl` for events and
stats, refcounted teardown on close. The per-frame paths
(`sstp_rx_worker` in `sstp_demux.c`, `sstp_chan_start_xmit` in
`sstp_chan.c`) are TODOs — they currently bump counters but do
not actually move PPP frames. Loading the module is harmless;
attaching a session creates a registered channel that ignores
TX and never delivers RX until those TODOs land.

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

## Loading (not yet supported in this container)

```sh
sudo insmod kmod/sstp.ko       # requires ppp_generic loaded first
sudo rmmod sstp                # safe even with attached sessions:
                               # rmmod will wait for refs to drop
```

A loadable test against a real kernel is out of scope for the
dev container; CI will need a VM (or a `kunit`-style harness).

## Next steps

In rough order:

1. **Receive demux** (`sstp_demux.c`): `kernel_recvmsg` on the
   kTLS socket, parse `[MS-SSTP] §2.2.3` data-packet framing,
   `ppp_input(&chan, skb)` per complete PPP frame inside.
2. **Transmit framing** (`sstp_chan.c`): wrap outgoing PPP frames
   in the SSTP data-packet header, `kernel_sendmsg` on the kTLS
   socket. Handle `-EAGAIN` via the usual `sk_write_space`
   callback and `ppp_output_wakeup`.
3. **TLS rekey handling**: detect TLS 1.3 KeyUpdate records,
   emit `SSTP_EVT_TLS_REKEY_NEEDED`, suspend the data path until
   userspace reinstalls crypto info via `setsockopt(SOL_TLS, ...)`.
4. **Unit binding**: expose `ppp_channel_index()` so userspace can
   `PPPIOCATTCHAN` + `PPPIOCCONNECT` on its own `/dev/ppp` fd to
   bind the kernel-side channel to the PPP unit it created earlier
   (or invert the model — kernel allocates the unit too — once
   the open question in `kernel-abi/sstp.h` is settled).
