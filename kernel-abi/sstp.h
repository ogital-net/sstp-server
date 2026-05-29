/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
 *
 * sstp.h — UAPI for a future in-kernel SSTP channel driver.
 *
 * **STATUS: DRAFT.** This header is not implemented anywhere yet. It
 * exists to anchor the eventual sstp-server v0.x kernel-module data
 * path against a concrete ABI so the userspace side can be written
 * with that handoff in mind. Numbers, struct layouts, and even the
 * top-level model are subject to change until the kmod is real and a
 * kernel maintainer has weighed in.
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
 *      `SSTP_IOC_ATTACH` (below), handing in:
 *        - the raw TCP socket fd carrying the TLS session, with
 *          kTLS RX/TX crypto already installed via
 *          `setsockopt(SOL_TLS, ...)` by the userspace TLS library,
 *        - the PPP unit number to bind to.
 *
 *      kTLS is the **only** supported handoff. If the negotiated
 *      cipher suite or TLS version is not kTLS-eligible (today:
 *      TLS 1.2 / 1.3 with AES-GCM or ChaCha20-Poly1305), the
 *      attach fails with `-EOPNOTSUPP` and userspace stays on the
 *      slow path. Pulling a userspace TLS stack into the kernel
 *      is explicitly out of scope.
 *
 *   3. The kernel registers a PPP channel for that unit
 *      (`ppp_register_channel`), takes over reads from the TCP
 *      socket, runs AEAD decrypt via kTLS, demuxes SSTP frames,
 *      and pushes IP packets straight at the `pppN` netdev.
 *      Transmit is the reverse path. Per-packet userspace
 *      involvement drops to zero.
 *
 *   4. Userspace keeps the control plane: SSTP keep-alives, Crypto
 *      Binding verification (already done at handoff), graceful
 *      shutdown via `SSTP_IOC_DETACH`. The kernel signals
 *      exceptional conditions (TLS fatal alert, peer FIN, etc.)
 *      back to userspace via `POLLIN` on a control fd returned
 *      from `SSTP_IOC_ATTACH`.
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
 * a different major; minor bumps are additive (new optional
 * fields in tail-padded structs).
 * ---------------------------------------------------------------- */

#define SSTP_ABI_VERSION_MAJOR  0
#define SSTP_ABI_VERSION_MINOR  1

/* ----------------------------------------------------------------
 * Flags for struct sstp_attach.flags
 * ---------------------------------------------------------------- */

/* Peer negotiated PPP header compression (PFC, RFC 1661 §6.5).
 * Kernel parser accepts both 1-byte and 2-byte protocol fields. */
#define SSTP_F_PFC          (1u << 0)

/* Peer negotiated address-and-control compression (ACFC, RFC 1661
 * §6.6). Kernel parser accepts frames with the leading FF 03 elided. */
#define SSTP_F_ACFC         (1u << 1)

/* Reserved for IPV6CP — flips on the kernel's IPv6 fast path. */
#define SSTP_F_IPV6         (1u << 2)

/* ----------------------------------------------------------------
 * Attach payload
 *
 * Passed by pointer to SSTP_IOC_ATTACH. All fields are populated
 * by userspace; the kernel writes back a session fd via the
 * `session_fd` field on success.
 * ---------------------------------------------------------------- */

struct sstp_attach {
	/* Input: caller's view of the ABI. Kernel verifies. */
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

	/* Input: PPP unit number returned by PPPIOCGUNIT on the
	 * userspace unit fd. The kernel attaches the SSTP channel
	 * to this unit via `ppp_register_channel` + the equivalent
	 * of PPPIOCCONNECT. The unit itself stays owned by
	 * userspace; the kernel only takes a reference. */
	__s32   ppp_unit;

	/* Input: SSTP_F_* flags (see above). */
	__u32   flags;

	/* Input: MTU negotiated by LCP. Kernel uses this to size
	 * SKB allocations on the receive path. 0 = use default
	 * (1500). */
	__u32   mtu;

	/* Output: session fd. Polling this returns POLLIN when the
	 * kernel needs userspace attention (peer disconnect, fatal
	 * TLS alert, kTLS rekey required). Reading returns a
	 * `struct sstp_event` (TBD). Closing this fd detaches the
	 * channel and releases the references taken at attach. */
	__s32   session_fd;

	/* Reserved — must be zero. Future versions may use these
	 * for e.g. an EAP session key for periodic rekey, or an
	 * accounting handoff fd. */
	__u32   reserved[4];
};

/* ----------------------------------------------------------------
 * Detach payload (currently empty)
 *
 * SSTP_IOC_DETACH is issued on the session_fd returned by attach.
 * Closing the fd has the same effect; the explicit ioctl exists
 * so userspace can wait for the in-flight kernel work to drain
 * before closing.
 * ---------------------------------------------------------------- */

struct sstp_detach {
	__u32   reserved[4];
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
	__u64   sstp_frames_rx;
	__u64   sstp_frames_tx;
	__u64   sstp_malformed;         /* bad length, bad version, ... */
	__u64   ppp_frames_rx;          /* PPP frames pushed up to ppp_generic */
	__u64   ppp_frames_tx;          /* PPP frames received from ppp_generic */
	__u64   reserved[8];
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
#define SSTP_IOC_DETACH         _IOW (SSTP_IOC_MAGIC, 0x81, struct sstp_detach)
#define SSTP_IOC_GETSTATS       _IOR (SSTP_IOC_MAGIC, 0x82, struct sstp_stats)

/* Returns the PPP channel index assigned by `ppp_register_channel()`
 * at attach time. Userspace passes this to `PPPIOCATTCHAN` on its
 * `/dev/ppp` handle and then `PPPIOCCONNECT` on the unit fd to bind
 * the SSTP channel to the PPP unit it negotiated earlier. Issued on
 * the session_fd. */
#define SSTP_IOC_GET_CHAN_INDEX _IOR (SSTP_IOC_MAGIC, 0x83, __s32)

/* ----------------------------------------------------------------
 * Event stream (read from session_fd)
 *
 * Sized so a single `read(2)` returns a whole event. The kernel
 * never partial-reads; short reads return -EINVAL.
 * ---------------------------------------------------------------- */

#define SSTP_EVT_PEER_CLOSED        1   /* TCP FIN or RST from peer */
#define SSTP_EVT_TLS_FATAL_ALERT    2   /* alert code in `arg` */
#define SSTP_EVT_TLS_REKEY_NEEDED   3   /* userspace must do the rekey
                                         * dance and re-install kTLS
                                         * crypto via setsockopt */
#define SSTP_EVT_PROTOCOL_ERROR     4   /* malformed SSTP that aborts
                                         * the session per [MS-SSTP]
                                         * §3.2.5.2.5 */

struct sstp_event {
	__u32   type;     /* SSTP_EVT_* */
	__u32   arg;      /* type-specific payload, e.g. TLS alert code */
	__u64   timestamp_ns; /* CLOCK_MONOTONIC */
};

/* ============================================================
 * Open questions
 * ============================================================
 *
 * 1. **PPP channel vs PPP unit ownership.**
 *    The model above keeps the unit in userspace and registers a
 *    *channel* against it. Cleaner inversion: kernel owns both,
 *    userspace just hands in the negotiated config (MRU, ACCM,
 *    IPCP-resolved addresses). Decision punted until the kmod
 *    is real; today's `Unit` type in `crate::kppp` covers either.
 *
 * 2. **Per-session vs shared event fd.**
 *    `epoll` against N session_fds is the obvious shape and
 *    matches our per-core tokio worker layout. A single shared
 *    fd would need its own demux scheme. Default: per-session.
 *
 * 3. **Accounting.**
 *    Byte counters live on the `pppN` netdev (kernel maintains
 *    them already). RADIUS Interim-Update payloads come from
 *    `rtnetlink` IFLA_STATS64, not from this device. Nothing in
 *    this header needs to change for accounting.
 *
 * 4. **Capability model.**
 *    `/dev/sstp` open requires CAP_NET_ADMIN. Attach additionally
 *    requires the calling process to own (or have inherited) both
 *    `tcp_fd` and the PPP unit fd `ppp_unit` refers to. No
 *    cross-namespace handoff in v0.
 */

#endif /* _UAPI_LINUX_SSTP_H */
