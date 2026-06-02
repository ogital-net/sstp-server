// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * sstp_chan.c — `struct ppp_channel` ops (TX path).
 *
 * `ppp_generic` invokes `start_xmit` while holding the channel's
 * `pch->downl` spinlock (see `ppp_channel_push()` in
 * `drivers/net/ppp/ppp_generic.c`). The call site is therefore
 * atomic, so we cannot synchronously issue `kernel_sendmsg()`
 * here: with kTLS installed, that path dispatches to
 * `tls_sw_sendmsg()`, whose first action is `lock_sock(sk)` —
 * a sleepable acquire that schedules under contention.
 *
 * The TX path is therefore split in two:
 *
 *   start_xmit  (atomic, brief)        tx_worker  (process ctx)
 *   ───────────────────────────        ─────────────────────────
 *   skb_queue_tail(&s->tx_q, skb)  →   skb_dequeue(&s->tx_q)
 *   queue_work(s->wq, &s->tx_work)     build SSTP/PPP prefix iovec
 *                                      kernel_sendmsg(s->tcp_sock)
 *                                      kfree_skb on success
 *
 * Backpressure: `start_xmit` returns 0 once `tx_q` reaches
 * `SSTP_TX_Q_CAP`, which tells `ppp_generic` to hold the skb on
 * its own per-channel xq. `tx_worker` calls `ppp_output_wakeup()`
 * (process context — safe) once it has drained below half-cap so
 * those skbs come back in.
 *
 * On `-EAGAIN` from `kernel_sendmsg` the skb is re-headed onto
 * `tx_q` and the worker exits; the `sk_write_space` hook in
 * `sstp_demux.c` re-queues `tx_work` once the socket buffer
 * drains. Hard errors / short writes desync the TLS stream and
 * tear the session down.
 */

#include <linux/compiler_attributes.h>
#include <linux/errno.h>
#include <linux/net.h>
#include <linux/ppp_channel.h>
#include <linux/ppp_defs.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uio.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include "sstp_internal.h"

static int sstp_chan_start_xmit(struct ppp_channel *chan, struct sk_buff *skb)
{
	struct sstp_session *s = chan->private;
	size_t total = SSTP_HEADER_LEN + 2 + skb->len;

	if (READ_ONCE(s->closing)) {
		kfree_skb(skb);
		return 1;
	}
	if (total > SSTP_MAX_PACKET_LEN) {
		atomic64_inc(&s->stats_sstp_malformed);
		kfree_skb(skb);
		return 1;
	}

	/* Backpressure: cap the deferred queue. Returning 0 tells
	 * ppp_generic to hold the skb on its own per-channel xq;
	 * tx_worker calls ppp_output_wakeup() once it has drained
	 * enough room. */
	if (skb_queue_len(&s->tx_q) >= SSTP_TX_Q_CAP)
		return 0;

	skb_queue_tail(&s->tx_q, skb);
	queue_work(s->wq, &s->tx_work);
	return 1;
}

/* Batch up to this many PPP skbs into one kernel_sendmsg. With
 * MTU=1500 the worst-case payload is 8 * (4 + 2 + 1500) = ~12 KB,
 * which fits comfortably under TLS-SW's 16 KB-plaintext-per-record
 * cap (RFC 8446 §5.1). Packing N skbs into a single sendmsg lets
 * kTLS-SW emit one TLS record (one AEAD invocation, one record
 * header, one TCP segment when possible) instead of N — the
 * single biggest reason the kmod path is per-frame heavier than
 * the userspace TUN path, which writes the SSTP header + body
 * into one contiguous buffer per IP packet. */
#define SSTP_TX_BATCH_MAX 8
#define SSTP_TX_HDR_STRIDE (SSTP_HEADER_LEN + 2) /* 6 bytes */
#define SSTP_TX_BATCH_BYTES_MAX (14 * 1024) /* < 16 KB TLS record */

void sstp_tx_worker(struct work_struct *w)
{
	struct sstp_session *s = container_of(w, struct sstp_session, tx_work);
	struct sk_buff *batch[SSTP_TX_BATCH_MAX];
	u8 hdrs[SSTP_TX_BATCH_MAX * SSTP_TX_HDR_STRIDE];
	struct kvec iov[SSTP_TX_BATCH_MAX * 2];
	bool drained = false;
	int loops = 0;

	while (!READ_ONCE(s->closing)) {
		struct msghdr msg = {
			.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
		};
		size_t total = 0;
		unsigned int n = 0;
		unsigned int kn = 0;
		struct sk_buff *skb;
		int ret;
		unsigned int i;

		/* Build a batch by draining tx_q. Stop at the count cap,
		 * the byte cap, or when the queue is empty. */
		while (n < SSTP_TX_BATCH_MAX) {
			size_t frame;
			u8 *hdr;

			skb = skb_dequeue(&s->tx_q);
			if (!skb)
				break;
			frame = SSTP_TX_HDR_STRIDE + skb->len;
			if (n > 0 && total + frame > SSTP_TX_BATCH_BYTES_MAX) {
				/* Doesn't fit in the current batch.
				 * Re-head; next iteration will pick it up. */
				skb_queue_head(&s->tx_q, skb);
				break;
			}

			hdr = hdrs + n * SSTP_TX_HDR_STRIDE;
			/* [MS-SSTP] §2.2.3 data-packet header. */
			hdr[0] = SSTP_VERSION_1_0;
			hdr[1] = 0; /* C = 0 (data) */
			hdr[2] = (frame >> 8) & 0x0F;
			hdr[3] = frame & 0xFF;
			hdr[4] = PPP_ALLSTATIONS;
			hdr[5] = PPP_UI;

			iov[kn].iov_base = hdr;
			iov[kn].iov_len = SSTP_TX_HDR_STRIDE;
			kn++;
			iov[kn].iov_base = skb->data;
			iov[kn].iov_len = skb->len;
			kn++;

			batch[n++] = skb;
			total += frame;
		}

		if (n == 0)
			break;

		ret = kernel_sendmsg(s->tcp_sock, &msg, iov, kn, total);

		if (ret == (int)total) {
			atomic64_add(n, &s->stats_ppp_frames_tx);
			atomic64_add(n, &s->stats_sstp_frames_tx);
			/* One TLS record per sendmsg under kTLS-SW: the
			 * whole batch is one record, not n. */
			atomic64_inc(&s->stats_tls_records_tx);
			sstp_dbg("tx session=%p batch=%u sstp_len=%zu\n", s, n, total);
			for (i = 0; i < n; i++)
				kfree_skb(batch[i]);
			drained = true;
			/* Bound per-wakeup work so we don't starve the
			 * workqueue. Loop budget is per-batch now, so
			 * one iteration here moves up to BATCH_MAX skbs. */
			if (++loops >= 8) {
				queue_work(s->wq, &s->tx_work);
				break;
			}
			continue;
		}

		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
			/* Socket buffer full. Re-head every skb in
			 * reverse order so the original FIFO ordering
			 * is preserved when sk_write_space requeues us. */
			for (i = n; i > 0; i--)
				skb_queue_head(&s->tx_q, batch[i - 1]);
			sstp_dbg("tx EAGAIN session=%p batch=%u sstp_len=%zu qlen=%u\n", s, n,
				 total, skb_queue_len(&s->tx_q));
			break;
		}

		/* Short write or hard error: TCP stream is now
		 * ambiguous (kTLS may have absorbed part of the
		 * batch's plaintext into an open record). Tear the
		 * session down. */
		atomic64_inc(&s->stats_tx_send_errors);
		pr_warn_ratelimited(SSTP_MOD_NAME
				    ": sendmsg ret=%d (wanted %zu, batch=%u); aborting\n",
				    ret, total, n);
		sstp_session_emit(s, SSTP_EVT_TLS_FATAL_ALERT, ret < 0 ? (u32)-ret : 0);
		WRITE_ONCE(s->closing, true);
		for (i = 0; i < n; i++)
			kfree_skb(batch[i]);
		break;
	}

	/* If we made room, let ppp_generic re-push anything it was
	 * holding because a previous start_xmit returned 0. Safe to
	 * call from process context. */
	if (drained && skb_queue_len(&s->tx_q) < SSTP_TX_Q_CAP / 2)
		ppp_output_wakeup(&s->chan);
}

static int sstp_chan_ioctl(struct ppp_channel *chan __maybe_unused, unsigned int cmd __maybe_unused,
			   unsigned long arg __maybe_unused)
{
	/* No channel-specific ioctls — everything goes through the
	 * session_fd. */
	return -ENOTTY;
}

const struct ppp_channel_ops sstp_chan_ops = {
	.start_xmit = sstp_chan_start_xmit,
	.ioctl = sstp_chan_ioctl,
};
