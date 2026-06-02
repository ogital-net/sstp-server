/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
 *
 * sstp.h — UAPI for the in-tree SSTP channel driver.
 *
 * **STATUS: v0.3, frozen.** This is the userspace ABI shipped by
 * the sstp.ko kernel module under [kmod/](../kmod/) and consumed
 * by the sstp-server userspace daemon. Frozen for the v0.x
 * series; incompatible changes bump SSTP_ABI_VERSION_MAJOR.
 * Additive minor revisions extend `struct sstp_stats` and reserve
 * additional ioctl numbers; clients that compiled against an
 * older minor see a strict prefix of the current struct.
 *
 * ============================================================
 * Model
 * ============================================================
 *
 * SSTP terminates TLS over TCP/443. Per-packet TLS in userspace plus
 * per-packet PPP framing through the unit fd is the bottleneck that
 * keeps us off-pace with `accel-ppp` for raw throughput. The kmod
 * removes that bottleneck by:
 *
 *   1. Letting userspace do the TLS handshake, SSTP negotiation,
 *      PPP LCP / auth / IPCP — i.e. everything stateful and
 *      cryptographically subtle. None of this is on the data path.
 *
 *   2. After IPCP, userspace opens `/dev/sstp` and issues
 *      `SSTP_IOC_ATTACH` (below), handing in the raw TCP socket fd
 *      carrying the TLS session, with kTLS RX/TX crypto already
 *      installed via `setsockopt(SOL_TLS, ...)` by the userspace TLS
 *      library.
 *
 *      kTLS is the **only** supported handoff. If the negotiated
 *      cipher suite or TLS version is not kTLS-eligible (today:
 *      TLS 1.2 / 1.3 with AES-GCM or ChaCha20-Poly1305), the
 *      attach fails with `-EOPNOTSUPP` and userspace stays on the
 *      slow path. Pulling a userspace TLS stack into the kernel
 *      is explicitly out of scope.
 *
 *   3. The kernel registers a PPP channel (`ppp_register_channel`)
 *      and returns a fresh session fd. Userspace fetches the
 *      channel index via `SSTP_IOC_GET_CHAN_INDEX`, then binds the
 *      channel to its already-created `pppN` unit using the
 *      standard ppp_generic ABI (`PPPIOCATTCHAN` on a fresh
 *      `/dev/ppp` fd, then `PPPIOCCONNECT` against the unit
 *      number). The kmod intentionally does *not* own the unit
 *      binding — `ppp_connect_channel()` is unexported in mainline
 *      ppp_generic, and routing the bind through `vfs_ioctl()` from
 *      kernel context is not worth the simplicity tradeoff.
 *
 *   4. Once the channel↔unit binding is in place, the kernel takes
 *      over reads from the TCP socket, runs AEAD decrypt via kTLS,
 *      demuxes SSTP frames, and pushes IP packets straight at the
 *      `pppN` netdev. Transmit is the reverse path. Per-packet
 *      userspace involvement drops to zero on the data plane.
 *
 *   5. Userspace keeps the control plane: SSTP keep-alives, Crypto
 *      Binding verification (already done at handoff), graceful
 *      shutdown via close-on-session_fd. The kernel signals
 *      exceptional conditions (TLS fatal alert, peer FIN, control
 *      packets, KeyUpdate) back to userspace via `POLLIN` on the
 *      session fd; events are read with `read(2)` and the queued
 *      control-packet payloads are drained with
 *      `SSTP_IOC_RECV_CONTROL`.
 *
 * This mirrors the `pppol2tp` shape (userspace negotiates, kernel
 * runs steady-state) and is intentionally narrow — we don't carry
 * the SSTP control-message vocabulary into the kernel, only the
 * post-handshake framing.
 *
 * ============================================================
 * Cross-references
 * ============================================================
 *
 * [MS-SSTP]   Microsoft Open Specification, v20210625.
 *             §2.2.3 (data packet framing) drives the kernel
 *             parser; §3.2.5 (state machine) stays in userspace.
 *
 * kTLS        Documentation/networking/tls.rst (kernel tree).
 *             RX/TX offload is mandatory; the attach ioctl rejects
 *             any tcp_fd whose `SOL_TLS` state isn't fully
 *             populated. TLS 1.3 KeyUpdate is signalled back to
 *             userspace via `SSTP_EVT_TLS_REKEY_NEEDED`; userspace
 *             handles the KeyUpdate record cooperatively and
 *             reinstalls fresh crypto info with `setsockopt`.
 *
 * ppp_generic drivers/net/ppp/ppp_generic.c — the PPP channel API
 *             we register against (`ppp_register_channel`,
 *             `ppp_input`, etc.).
 */

#ifndef _UAPI_LINUX_SSTP_H
#define _UAPI_LINUX_SSTP_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* ----------------------------------------------------------------
 * Char device
 *
 * `/dev/sstp` — single shared char dev. Each successful
 * `SSTP_IOC_ATTACH` returns a new fd (via the third ioctl arg's
 * out field) that owns the session; closing it triggers detach.
 * Multiple concurrent sessions are independent: there is no
 * global state visible to userspace beyond the device node.
 * ---------------------------------------------------------------- */

#define SSTP_DEVICE_NAME "sstp"

/* ----------------------------------------------------------------
 * ABI version
 *
 * Bumped on any incompatible change to the structs below.
 * Userspace MUST refuse to attach if the running kernel reports
 * a different major.
 *
 * History:
 *   0.1  initial draft (never released).
 *   0.2  RC: drop unused `ppp_unit` / `flags` / `reserved` fields
 *        from `struct sstp_attach`; drop `struct sstp_detach`
 *        entirely (close-on-fd is the supported teardown);
 *        replace `sstp_stats.reserved[]` with `evt_dropped`.
 * ---------------------------------------------------------------- */

#define SSTP_ABI_VERSION_MAJOR  0
#define SSTP_ABI_VERSION_MINOR  3

/* History:
 *   0.1  initial draft (never released).
 *   0.2  RC: drop unused `ppp_unit` / `flags` / `reserved` fields
 *        from `struct sstp_attach`; drop `struct sstp_detach`
 *        entirely (close-on-fd is the supported teardown);
 *        replace `sstp_stats.reserved[]` with `evt_dropped`.
 *   0.3  Frozen: add `SSTP_IOC_SEND_CONTROL` so userspace can emit
 *        SSTP control frames without keeping a writable dup of the
 *        TCP fd post-attach; add `SSTP_IOC_REKEY_TX` /
 *        `SSTP_IOC_REKEY_RX` (return -ENOSYS — reserved but not
 *        planned for v0.x; any non-app-data TLS record post-attach
 *        is fatal, matching HAProxy's AWS-LC + kTLS posture); extend
 *        `struct sstp_stats` with `ctrl_frames_rx`, `ctrl_frames_tx`,
 *        and `tx_send_errors`. */

/* ----------------------------------------------------------------
 * Attach payload
 *
 * Passed by pointer to SSTP_IOC_ATTACH. Caller fills `abi_major`,
 * `abi_minor`, `tcp_fd`, and `mtu`; kernel writes back
 * `session_fd` on success.
 * ---------------------------------------------------------------- */

struct sstp_attach {
	/* Input: caller's view of the ABI. Kernel verifies that
	 * `abi_major` matches `SSTP_ABI_VERSION_MAJOR`; `abi_minor`
	 * is informational and the kernel echoes its own minor on
	 * the way out (caller may use it to gate optional features
	 * once a 0.x with optional bits ships). */
	__u16   abi_major;
	__u16   abi_minor;

	/* Input: file descriptor of the TCP socket carrying the
	 * already-completed TLS session. Must be a stream socket in
	 * ESTABLISHED state with kTLS RX **and** TX crypto already
	 * installed (i.e. the userspace TLS library has issued
	 * `setsockopt(SOL_TLS, TLS_RX/TX, ...)` after the handshake
	 * completed). The kernel verifies both directions are
	 * configured and fails the attach with `-EOPNOTSUPP`
	 * otherwise. The kernel takes a reference; caller may close
	 * its fd after the ioctl returns. */
	__s32   tcp_fd;

	/* Input: MTU negotiated by LCP. Kernel uses this to size
	 * SKB allocations on the receive path and as the registered
	 * channel's `mtu`. 0 = use default (1500). */
	__u32   mtu;

	/* Output: session fd. Polling this returns POLLIN when the
	 * kernel needs userspace attention (peer disconnect, fatal
	 * TLS alert, kTLS rekey required, queued control packet).
	 * Reading returns one `struct sstp_event`. Closing this fd
	 * detaches the channel and releases the references taken at
	 * attach. */
	__s32   session_fd;
};

/* ----------------------------------------------------------------
 * Statistics
 *
 * Returned by SSTP_IOC_GETSTATS on a session_fd. Userspace can
 * also reach the per-unit byte counters via `ip -s link show pppN`;
 * these are the SSTP-channel-specific counters that aren't
 * visible through the netdev (TLS records seen, decrypt errors,
 * malformed-SSTP-frame drops, etc.).
 * ---------------------------------------------------------------- */

struct sstp_stats {
	__u64   tls_records_rx;
	__u64   tls_records_tx;
	__u64   tls_decrypt_errors;     /* AEAD tag mismatch */
	__u64   sstp_frames_rx;         /* total demuxed SSTP frames (data+ctrl) */
	__u64   sstp_frames_tx;         /* total SSTP frames emitted (data+ctrl) */
	__u64   sstp_malformed;         /* bad length, bad version, ... */
	__u64   ppp_frames_rx;          /* PPP frames pushed up to ppp_generic */
	__u64   ppp_frames_tx;          /* PPP frames received from ppp_generic */
	__u64   evt_dropped;            /* events coalesced/dropped because the
	                                 * userspace event ring was full */
	/* v0.3 additions: control-frame plane and TX failure counters.
	 * Older callers that read sizeof(v0.2 sstp_stats) bytes with
	 * a pre-v0.3 binding see the same struct prefix; the kernel
	 * always writes the full v0.3 struct. */
	__u64   ctrl_frames_rx;         /* C=1 frames demuxed and queued for
	                                 * userspace via SSTP_IOC_RECV_CONTROL */
	__u64   ctrl_frames_tx;         /* C=1 frames emitted via
	                                 * SSTP_IOC_SEND_CONTROL */
	__u64   tx_send_errors;         /* hard kernel_sendmsg failures and
	                                 * short writes that aborted the
	                                 * session (excludes -EAGAIN, which is
	                                 * surfaced to the caller and not
	                                 * counted as an error) */
};

/* ----------------------------------------------------------------
 * ioctl numbers
 *
 * Type byte `'S'` (0x53) is provisional; the upstream allocation
 * will need to come from <Documentation/userspace-api/ioctl/
 * ioctl-number.rst>. The currently-unallocated `'S' 0x80..0xff`
 * range is one candidate.
 * ---------------------------------------------------------------- */

#define SSTP_IOC_MAGIC          'S'

#define SSTP_IOC_ATTACH         _IOWR(SSTP_IOC_MAGIC, 0x80, struct sstp_attach)

/* Detach: take no payload, just signal the kernel that userspace is
 * about to close the session fd. Closing the fd alone is enough; the
 * explicit ioctl exists so a caller that wants to see the in-flight
 * work drained can sequence detach → poll-for-POLLHUP → close. */
#define SSTP_IOC_DETACH         _IO  (SSTP_IOC_MAGIC, 0x81)

#define SSTP_IOC_GETSTATS       _IOR (SSTP_IOC_MAGIC, 0x82, struct sstp_stats)

/* Returns the PPP channel index assigned by `ppp_register_channel()`
 * at attach time. Userspace passes this to `PPPIOCATTCHAN` on its
 * `/dev/ppp` handle and then `PPPIOCCONNECT` on the unit fd to bind
 * the SSTP channel to the PPP unit it negotiated earlier. Issued on
 * the session_fd. */
#define SSTP_IOC_GET_CHAN_INDEX _IOR (SSTP_IOC_MAGIC, 0x83, __s32)

/* Pull one queued SSTP control packet (C=1, header stripped) into
 * the user-supplied buffer. Returns the payload length on success,
 * 0 if the queue is empty, or -errno. The caller's buffer must be
 * at least SSTP_CONTROL_MAX bytes; smaller buffers cause the
 * frame to be dropped (not requeued) with -EMSGSIZE. Issued on
 * the session_fd; pair with a poll() on the event fd for
 * SSTP_EVT_CONTROL_PACKET. */
#define SSTP_CONTROL_MAX        4096

struct sstp_recv_control {
	__u32   buf_len;            /* in: size of `buf` */
	__u32   payload_len;        /* out: bytes written to `buf` */
	__u64   buf;                /* in: __u64-cast user pointer */
};

#define SSTP_IOC_RECV_CONTROL   _IOWR(SSTP_IOC_MAGIC, 0x84, struct sstp_recv_control)

/* Push one SSTP control packet (C=1) onto the wire. Userspace
 * passes the SSTP control-message body — i.e. everything after the
 * 4-byte outer SSTP header ([MS-SSTP] §2.2.1); the kernel prepends
 * the header (version 1.0, C=1, length = 4 + buf_len) and writes
 * the resulting frame to the kTLS socket as a single TLS record.
 *
 * Bounded by `SSTP_CONTROL_MAX - SSTP_HEADER_LEN`; the kernel
 * rejects oversized payloads with -EMSGSIZE.
 *
 * Always non-blocking. On socket-buffer backpressure the kernel
 * returns -EAGAIN; userspace should poll the session fd for
 * `EPOLLOUT` and retry once it fires. Hard send errors (anything
 * other than -EAGAIN/-EWOULDBLOCK) abort the session: the kernel
 * emits `SSTP_EVT_TLS_FATAL_ALERT`, transitions to closing, and
 * subsequent SEND_CONTROL calls return -EPIPE.
 *
 * Issued on the session_fd. The TCP fd reference held by the
 * kernel since attach is the sole writer once userspace starts
 * using this ioctl; userspace may close its own dup of the TCP fd
 * after attach returns.
 */
struct sstp_send_control {
	__u32   buf_len;            /* in: payload bytes at `buf` */
	__u32   reserved;           /* must be zero */
	__u64   buf;                /* in: __u64-cast user pointer */
};

#define SSTP_IOC_SEND_CONTROL   _IOW (SSTP_IOC_MAGIC, 0x85, struct sstp_send_control)

/* TLS 1.3 cooperative rekey (KeyUpdate / NewSessionTicket).
 *
 * **Reserved but not planned for v0.x.** The kernel returns
 * -ENOSYS unconditionally. Any non-application-data TLS record
 * arriving post-attach (KeyUpdate, NewSessionTicket, alerts) is
 * treated as fatal: the kmod emits `SSTP_EVT_TLS_REKEY_NEEDED`,
 * sets `closing`, and userspace tears the session down. This
 * matches HAProxy's AWS-LC + kTLS handling (HAProxy's vanilla
 * OpenSSL path *does* support cooperative rekey via
 * `BIO_CTRL_SET_KTLS`; the AWS-LC / BoringSSL path does not, and
 * neither does ours). The shape below is preserved for forward
 * compatibility — if a future minor revisits this for long-
 * running tunnels approaching the AES-GCM per-key record-count
 * ceiling, the ioctl signature is already specified: userspace
 * points the kernel at a `tls12_crypto_info_*` (or 1.3 equivalent)
 * blob whose layout the kernel already knows, and the kmod swaps
 * the new keys in under the socket lock.
 *
 * `cipher_type` is one of the `TLS_CIPHER_*` constants from
 * <linux/tls.h>; `info_len` is the size of the blob the kernel
 * expects for that cipher.
 */
struct sstp_rekey {
	__u32   cipher_type;        /* TLS_CIPHER_* from <linux/tls.h> */
	__u32   info_len;           /* sizeof(*tls12_crypto_info_*) */
	__u64   crypto_info;        /* __u64-cast user pointer */
};

#define SSTP_IOC_REKEY_TX       _IOW (SSTP_IOC_MAGIC, 0x86, struct sstp_rekey)
#define SSTP_IOC_REKEY_RX       _IOW (SSTP_IOC_MAGIC, 0x87, struct sstp_rekey)

/* ----------------------------------------------------------------
 * Event stream (read from session_fd)
 *
 * Sized so a single `read(2)` returns a whole event. The kernel
 * never partial-reads; short reads return -EINVAL.
 *
 * Backpressure for SSTP_IOC_SEND_CONTROL is signalled through
 * `poll(session_fd)` returning `EPOLLOUT | EPOLLWRNORM` rather
 * than as an event — there is no `SSTP_EVT_TX_READY`. The session
 * fd reports `EPOLLOUT` whenever the underlying TCP socket has
 * write space (the kmod hooks `sk_write_space` to propagate the
 * wakeup).
 * ---------------------------------------------------------------- */

#define SSTP_EVT_PEER_CLOSED        1   /* TCP FIN or RST from peer */
#define SSTP_EVT_TLS_FATAL_ALERT    2   /* alert code in `arg` */
#define SSTP_EVT_TLS_REKEY_NEEDED   3   /* userspace must do the rekey
                                         * dance and re-install kTLS
                                         * crypto via setsockopt */
#define SSTP_EVT_PROTOCOL_ERROR     4   /* malformed SSTP that aborts
                                         * the session per [MS-SSTP]
                                         * §3.2.5.2.5 */
#define SSTP_EVT_CONTROL_PACKET     5   /* an SSTP control packet (C=1)
                                         * was demuxed and queued for
                                         * userspace; pull it with
                                         * SSTP_IOC_RECV_CONTROL. `arg`
                                         * is the payload length (header
                                         * stripped). */

struct sstp_event {
	__u32   type;     /* SSTP_EVT_* */
	__u32   arg;      /* type-specific payload, e.g. TLS alert code */
	__u64   timestamp_ns; /* CLOCK_MONOTONIC */
};

#endif /* _UAPI_LINUX_SSTP_H */
