// SPDX-License-Identifier: GPL-2.0
/*
 * sstp_demux.c — receive data path skeleton.
 *
 * The kernel-side receive loop pulls bytes off the kTLS-equipped
 * TCP socket, parses [MS-SSTP] §2.2.3 framing, dispatches user-data
 * frames into ppp_input() and surfaces exceptional conditions
 * (peer close, TLS fatal alert) via sstp_session_emit().
 *
 * v0.1 status: the loop is stubbed. We register a sk_data_ready
 * callback on the TCP socket to learn when bytes arrive, and the
 * worker exists in skeleton form so the lifecycle (queue, cancel,
 * drain on close) is exercised end-to-end. Reading actual SSTP
 * frames is the next milestone.
 */

#include <linux/errno.h>
#include <linux/net.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include "sstp_internal.h"

void sstp_rx_worker(struct work_struct *w)
{
	struct sstp_session *s = container_of(w, struct sstp_session, rx_work);

	/* TODO(v0.1): kernel_recvmsg() on s->tcp_sock into a per-session
	 * reassembly buffer; parse SSTP data-packet framing; for each
	 * complete PPP frame inside, allocate an skb, copy the payload
	 * (minus the 4-byte SSTP header) into it, and call
	 * ppp_input(&s->chan, skb). Exceptional events (peer FIN,
	 * TLS fatal alert visible as -EBADMSG / -EIO) get translated
	 * to sstp_session_emit(s, SSTP_EVT_*, ...).
	 *
	 * The current skeleton just records that we ran, so the
	 * workqueue plumbing can be exercised by attach/detach tests
	 * before the per-frame logic lands. */
	if (READ_ONCE(s->closing))
		return;

	pr_debug(SSTP_MOD_NAME ": rx worker tick (chan=%d, unit=%d)\n",
		 ppp_channel_index(&s->chan), s->ppp_unit);
}

/*
 * Called from sstp_session_release() before the final reference
 * is dropped. Must guarantee the work item is no longer running
 * and will not be requeued.
 */
void sstp_demux_shutdown(struct sstp_session *s)
{
	/* Synchronous cancel; if the work is queued or running, this
	 * waits for it. After this returns, the work item is
	 * guaranteed not to touch the session again. */
	cancel_work_sync(&s->rx_work);

	if (s->wq) {
		flush_workqueue(s->wq);
		/* destroy_workqueue() in sstp_session_release() finalizes. */
	}
}
