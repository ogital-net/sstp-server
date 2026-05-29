/* SPDX-License-Identifier: GPL-2.0 */
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
	struct kref           ref;

	/* TCP socket carrying the kTLS-protected SSTP stream. We
	 * hold a counted reference via `get_file`; released on the
	 * final put. */
	struct file          *tcp_file;
	struct socket        *tcp_sock;

	/* PPP plumbing. The channel is registered against the unit
	 * number supplied at attach time. */
	struct ppp_channel    chan;
	int                   ppp_unit;      /* requested by userspace */
	bool                  chan_registered;

	/* Flags from struct sstp_attach.flags. */
	u32                   flags;
	u32                   mtu;

	/* Counters returned by SSTP_IOC_GETSTATS. Updated from the
	 * data path (rx workqueue + start_xmit) with `chan_lock`
	 * held for tx-side counters and atomically on the rx side. */
	struct sstp_stats     stats;
	spinlock_t            stats_lock;

	/* Event ring drained via read(session_fd). Bounded by
	 * SSTP_EVENT_QUEUE_CAP — entry SSTP_EVENT_QUEUE_CAP+1 wins
	 * by overwriting the most-recent event of the same type. */
	struct sstp_event     events[SSTP_EVENT_QUEUE_CAP];
	u32                   evt_head;      /* next slot to write */
	u32                   evt_tail;      /* next slot to read */
	u32                   evt_dropped;   /* coalesced events */
	wait_queue_head_t     evt_wait;
	spinlock_t            evt_lock;

	/* Receive worker. Pulls bytes out of the kTLS socket, runs
	 * the SSTP demux, hands user-data frames to ppp_input(). */
	struct work_struct    rx_work;
	struct workqueue_struct *wq;

	/* Set when the session is being torn down; the rx worker
	 * checks this and exits its loop. */
	bool                  closing;
	struct mutex          close_lock;
};

/* Reference counting. */
void sstp_session_get(struct sstp_session *s);
void sstp_session_put(struct sstp_session *s);

/* Attach path (sstp_attach.c). */
long sstp_do_attach(struct file *misc_file,
		    struct sstp_attach __user *uarg);

/* Session-fd file_operations + event helpers (sstp_event.c). */
extern const struct file_operations sstp_session_fops;
void sstp_session_emit(struct sstp_session *s, u32 type, u32 arg);

/* PPP channel ops (sstp_chan.c). */
extern const struct ppp_channel_ops sstp_chan_ops;

/* Data path (sstp_demux.c). */
void sstp_rx_worker(struct work_struct *w);
void sstp_demux_shutdown(struct sstp_session *s);

#endif /* _SSTP_INTERNAL_H */
