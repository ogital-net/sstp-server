// SPDX-License-Identifier: GPL-2.0
/*
 * sstp_demux.c — receive data path.
 *
 * Hooks `sk_data_ready` on the kTLS-equipped TCP socket; the worker
 * drains it via `kernel_recvmsg`, reassembles [MS-SSTP] §2.2.3
 * data-packet frames out of the byte stream, allocates skbs and
 * pushes the PPP payload up via `ppp_input()`. Control-packet
 * frames (C-bit = 1) are counted but otherwise dropped in v0.1 —
 * the only ones we expect post-handoff are Echo Request/Response
 * keepalives, whose handling will land alongside the userspace
 * event for it.
 */

#include <linux/errno.h>
#include <linux/net.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include "sstp_internal.h"

/* Hand a single PPP-payload skb up to ppp_generic. */
static void sstp_deliver_ppp(struct sstp_session *s,
			     const u8 *payload, u32 payload_len)
{
	struct sk_buff *skb;
	unsigned long flags;

	skb = dev_alloc_skb(payload_len);
	if (!skb) {
		spin_lock_irqsave(&s->stats_lock, flags);
		s->stats.sstp_malformed++;
		spin_unlock_irqrestore(&s->stats_lock, flags);
		return;
	}
	skb_put_data(skb, payload, payload_len);

	spin_lock_irqsave(&s->stats_lock, flags);
	s->stats.ppp_frames_rx++;
	spin_unlock_irqrestore(&s->stats_lock, flags);

	ppp_input(&s->chan, skb);
}

/*
 * Parse as many complete SSTP frames as are present in s->rx_buf.
 * Returns the number of bytes consumed; the caller compacts the
 * remainder back to the head of the buffer.
 *
 * On a framing error (bad version, length-too-small), emits
 * SSTP_EVT_PROTOCOL_ERROR and signals closing — once the stream
 * is desynced there is no safe way to resume.
 */
static u32 sstp_demux_parse(struct sstp_session *s)
{
	u32 off = 0;
	unsigned long flags;

	while (s->rx_len - off >= SSTP_HEADER_LEN) {
		const u8 *p = s->rx_buf + off;
		u8 ver = p[0];
		u8 c = p[1] & SSTP_C_BIT;
		u16 length = ((u16)p[2] << 8 | p[3]) & SSTP_LEN_MASK;

		if (ver != SSTP_VERSION_1_0 ||
		    length < SSTP_HEADER_LEN) {
			pr_warn_ratelimited(SSTP_MOD_NAME
				": bad framing v=0x%02x len=%u; aborting\n",
				ver, length);
			spin_lock_irqsave(&s->stats_lock, flags);
			s->stats.sstp_malformed++;
			spin_unlock_irqrestore(&s->stats_lock, flags);
			sstp_session_emit(s, SSTP_EVT_PROTOCOL_ERROR, ver);
			WRITE_ONCE(s->closing, true);
			return off;
		}
		if (length > s->rx_len - off)
			break; /* need more bytes */

		spin_lock_irqsave(&s->stats_lock, flags);
		s->stats.sstp_frames_rx++;
		spin_unlock_irqrestore(&s->stats_lock, flags);

		if (c == 0) {
			sstp_deliver_ppp(s, p + SSTP_HEADER_LEN,
					 length - SSTP_HEADER_LEN);
		} else {
			/* Control packet post-handoff. v0.1: counted +
			 * dropped. A future revision will forward keepalive
			 * requests/responses to userspace via the event fd
			 * so the hello timer can stay in userspace. */
			pr_debug(SSTP_MOD_NAME
				": dropped control packet (len=%u)\n", length);
		}
		off += length;
	}

	return off;
}

/* Drain the socket once. Returns the number of bytes received, or a
 * negative errno (with -EAGAIN meaning "no more data right now"). */
static int sstp_demux_recv_once(struct sstp_session *s)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec iov;
	int ret;

	if (s->rx_len >= SSTP_RX_BUF_CAP)
		return -ENOBUFS;

	iov.iov_base = s->rx_buf + s->rx_len;
	iov.iov_len  = SSTP_RX_BUF_CAP - s->rx_len;

	ret = kernel_recvmsg(s->tcp_sock, &msg, &iov, 1, iov.iov_len,
			     MSG_DONTWAIT);
	if (ret > 0) {
		s->rx_len += ret;
		spin_lock(&s->stats_lock);
		s->stats.tls_records_rx++;
		spin_unlock(&s->stats_lock);
	}
	return ret;
}

void sstp_rx_worker(struct work_struct *w)
{
	struct sstp_session *s = container_of(w, struct sstp_session, rx_work);
	int loops = 0;

	while (!READ_ONCE(s->closing)) {
		int rc = sstp_demux_recv_once(s);

		if (rc == 0) {
			sstp_session_emit(s, SSTP_EVT_PEER_CLOSED, 0);
			WRITE_ONCE(s->closing, true);
			break;
		}
		if (rc < 0 && rc != -ENOBUFS) {
			if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
				/* sk_data_ready will requeue when more
				 * bytes arrive. */
				break;
			}
			pr_warn_ratelimited(SSTP_MOD_NAME
				": recv error %d; aborting session\n", rc);
			sstp_session_emit(s, SSTP_EVT_TLS_FATAL_ALERT,
					  (u32)-rc);
			WRITE_ONCE(s->closing, true);
			break;
		}

		if (s->rx_len) {
			u32 consumed = sstp_demux_parse(s);

			if (consumed) {
				memmove(s->rx_buf, s->rx_buf + consumed,
					s->rx_len - consumed);
				s->rx_len -= consumed;
			}
		}

		/* Bound per-wakeup work so we don't starve the workqueue. */
		if (++loops >= 32) {
			queue_work(s->wq, &s->rx_work);
			break;
		}
	}
}

/*
 * sk_data_ready hook: bytes arrived on the TCP socket. Just queue
 * the worker — all parsing/copying happens in process context.
 */
static void sstp_sk_data_ready(struct sock *sk)
{
	struct sstp_session *s = sk->sk_user_data;

	if (likely(s) && !READ_ONCE(s->closing))
		queue_work(s->wq, &s->rx_work);
}

void sstp_demux_install_callback(struct sstp_session *s)
{
	struct sock *sk = s->tcp_sock->sk;

	write_lock_bh(&sk->sk_callback_lock);
	s->saved_data_ready = sk->sk_data_ready;
	s->saved_user_data  = sk->sk_user_data;
	sk->sk_user_data    = s;
	sk->sk_data_ready   = sstp_sk_data_ready;
	s->cb_installed     = true;
	write_unlock_bh(&sk->sk_callback_lock);
}

void sstp_demux_remove_callback(struct sstp_session *s)
{
	struct sock *sk;

	if (!s->cb_installed || !s->tcp_sock)
		return;
	sk = s->tcp_sock->sk;
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_data_ready = s->saved_data_ready;
	sk->sk_user_data  = s->saved_user_data;
	s->cb_installed   = false;
	write_unlock_bh(&sk->sk_callback_lock);
}

/*
 * Called from sstp_session_release() before the final reference
 * is dropped. Must guarantee the work item is no longer running
 * and will not be requeued.
 */
void sstp_demux_shutdown(struct sstp_session *s)
{
	sstp_demux_remove_callback(s);

	/* Synchronous cancel; if the work is queued or running, this
	 * waits for it. After this returns, the work item is
	 * guaranteed not to touch the session again. */
	cancel_work_sync(&s->rx_work);

	if (s->wq)
		flush_workqueue(s->wq);
}
