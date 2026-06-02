/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * sstp_internal.h — module-private definitions.
 *
 * Visibility: this header is intentionally *not* installed and is
 * not part of the SSTP UAPI. The UAPI is the standalone
 * <uapi/linux/sstp.h> (sourced from kernel-abi/sstp.h).
 */

#ifndef _SSTP_INTERNAL_H
#define _SSTP_INTERNAL_H

#include <linux/file.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/ppp_channel.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include <uapi/linux/sstp.h>

#define SSTP_MOD_NAME "sstp"

/*
 * Bounded queue / buffer caps. Defined at file scope (rather than
 * inside `struct sstp_session`) so they can be referenced from
 * other translation units without dragging the struct definition
 * along, and so the values appear in one obvious place.
 */
#define SSTP_TX_Q_CAP 64
#define SSTP_CTRL_Q_CAP 8
#define SSTP_RX_BUF_CAP 8192 /* > 2 * max SSTP frame */

/*
 * Verbose dev-only tracing. Compiles to a no-op unless the module
 * is built with `make DEBUG=1` (which adds `-DDEBUG` to ccflags;
 * see kmod/Kbuild). With DEBUG defined, pr_debug() expands to
 * printk(KERN_DEBUG ...); without it, the call vanishes (or is
 * routed through CONFIG_DYNAMIC_DEBUG, depending on kernel
 * config). Production builds therefore carry zero overhead even
 * on the per-packet path. Use freely — the gate is at compile
 * time.
 *
 * Convention: terse, comma-separated `key=val` fields, no
 * trailing punctuation. Mirror the userspace tracing target
 * names where possible (e.g. "tx", "rx", "demux", "evt") so an
 * operator with `dmesg -w` can grep alongside the daemon's
 * structured logs.
 */
#define sstp_dbg(fmt, ...) pr_debug(SSTP_MOD_NAME ": " fmt, ##__VA_ARGS__)

/* SSTP packet framing constants ([MS-SSTP] §2.2.1, §2.2.3). The
 * outer header is 4 bytes: version (1), reserved+C (1), 16-bit
 * LengthPacket (4-bit R + 12-bit total length). */
#define SSTP_VERSION_1_0 0x10
#define SSTP_HEADER_LEN 4
#define SSTP_LEN_MASK 0x0FFF /* 12-bit length field */
#define SSTP_C_BIT 0x01 /* control = 1, data = 0 */
#define SSTP_MAX_PACKET_LEN SSTP_LEN_MASK

/* Maximum number of queued SSTP_EVT_* events per session before we
 * coalesce-drop. Events are infrequent (peer close, TLS fatal,
 * rekey-needed, protocol error) so this is generous. */
#define SSTP_EVENT_QUEUE_CAP 16

/*
 * Per-attached-session state. Lives until the session_fd is closed
 * *and* the kernel's data-path workqueue has drained, whichever
 * comes later — managed via `kref`.
 */
struct sstp_session {
	struct kref ref;

	/* TCP socket carrying the kTLS-protected SSTP stream. We
	 * hold a counted reference via `get_file`; released on the
	 * final put. */
	struct file *tcp_file;
	struct socket *tcp_sock;

	/* PPP plumbing. The kernel registers a channel only; the unit
	 * binding is owned by userspace via PPPIOCATTCHAN/PPPIOCCONNECT
	 * against the index returned by SSTP_IOC_GET_CHAN_INDEX. */
	struct ppp_channel chan;
	bool chan_registered;

	u32 mtu;

	/* Counters surfaced by SSTP_IOC_GETSTATS. Bumped lock-free
	 * from the rx worker, start_xmit, the event emitter, and
	 * (for `evt_dropped`) the event-emit fast path. The ioctl
	 * snapshots them under no lock — torn reads of a single
	 * counter pair are harmless because every counter is
	 * monotonically increasing, and the snapshot is advisory. */
	atomic64_t stats_tls_records_rx;
	atomic64_t stats_tls_records_tx;
	atomic64_t stats_tls_decrypt_errors;
	atomic64_t stats_sstp_frames_rx;
	atomic64_t stats_sstp_frames_tx;
	atomic64_t stats_sstp_malformed;
	atomic64_t stats_ppp_frames_rx;
	atomic64_t stats_ppp_frames_tx;
	atomic64_t stats_evt_dropped;
	/* v0.3 additions. */
	atomic64_t stats_ctrl_frames_rx;  /* C=1 frames demuxed + queued */
	atomic64_t stats_ctrl_frames_tx;  /* C=1 frames emitted via SEND_CONTROL */
	atomic64_t stats_tx_send_errors;  /* hard kernel_sendmsg failures */

	/* Event ring drained via read(session_fd). Bounded by
	 * SSTP_EVENT_QUEUE_CAP — entry SSTP_EVENT_QUEUE_CAP+1 wins
	 * by overwriting the most-recent event of the same type. */
	struct sstp_event events[SSTP_EVENT_QUEUE_CAP];
	u32 evt_head; /* next slot to write */
	u32 evt_tail; /* next slot to read */
	wait_queue_head_t evt_wait;
	/* Wakes when the underlying TCP socket has write space. The
	 * sk_write_space hook fires this; poll(session_fd) pivots
	 * EPOLLOUT off it so SSTP_IOC_SEND_CONTROL callers know when
	 * to retry after -EAGAIN. */
	wait_queue_head_t tx_wait;
	spinlock_t evt_lock;

	/* Workers. Both run on the per-session ordered workqueue
	 * `wq`. The work_struct re-entry guard implicitly serialises
	 * each worker against itself, which is all we need:
	 *  - rx_work: drains the kTLS socket, runs the SSTP demux,
	 *    hands user-data frames to `ppp_input()`. Once-at-a-time
	 *    preserves PPP packet order.
	 *  - tx_work: drains `tx_q` (FIFO from start_xmit) and pushes
	 *    each frame down `kernel_sendmsg()`. Required because
	 *    ppp_generic invokes `start_xmit` while holding a
	 *    spinlock, and `tls_sw_sendmsg()`'s `lock_sock()` is
	 *    sleepable; the channel ops therefore enqueue here and
	 *    return, with the actual send happening in process
	 *    context.
	 */
	struct work_struct rx_work;
	struct workqueue_struct *wq;
	struct sk_buff_head tx_q;
	struct work_struct tx_work;

	/* RX reassembly buffer. SSTP frames are length-prefixed
	 * (max 4095 bytes per [MS-SSTP] §2.2.3) but can straddle
	 * TLS-record boundaries; we accumulate bytes here and parse
	 * complete frames out of the head. Accessed only from the
	 * rx_worker, so no lock needed. */
	u8 *rx_buf;
	u32 rx_len; /* bytes valid at head */

	/* SSTP control-packet queue. Demuxed C=1 frames are stashed
	 * here (payload only, header stripped) and userspace pulls
	 * them with SSTP_IOC_RECV_CONTROL after seeing the matching
	 * SSTP_EVT_CONTROL_PACKET event. Bounded; overflow drops
	 * the *new* frame and bumps stats.sstp_malformed. */
	struct sk_buff *ctrl_q[SSTP_CTRL_Q_CAP];
	u32 ctrl_q_head;
	u32 ctrl_q_tail;
	spinlock_t ctrl_q_lock;

	/* Original socket callbacks, saved at attach so we can
	 * restore them at detach without leaking our wakeup hook
	 * into a socket the caller may keep open. */
	void (*saved_data_ready)(struct sock *sk);
	void (*saved_write_space)(struct sock *sk);
	void *saved_user_data;
	bool cb_installed;

	/* Set when the session is being torn down; the rx worker
	 * checks this and exits its loop. */
	bool closing;
	struct mutex close_lock;
};

/* Reference counting. */
void sstp_session_get(struct sstp_session *s);
void sstp_session_put(struct sstp_session *s);

/* Attach path (sstp_attach.c). */
long sstp_do_attach(struct file *misc_file, struct sstp_attach __user *uarg);

/* Session-fd file_operations + event helpers (sstp_event.c). */
extern const struct file_operations sstp_session_fops;
void sstp_session_emit(struct sstp_session *s, u32 type, u32 arg);

/* PPP channel ops (sstp_chan.c). */
extern const struct ppp_channel_ops sstp_chan_ops;

/* Data path (sstp_demux.c). */
void sstp_rx_worker(struct work_struct *w);
void sstp_demux_shutdown(struct sstp_session *s);
void sstp_demux_install_callback(struct sstp_session *s);
void sstp_demux_remove_callback(struct sstp_session *s);

/* TX worker (sstp_chan.c). */
void sstp_tx_worker(struct work_struct *w);

#endif /* _SSTP_INTERNAL_H */
