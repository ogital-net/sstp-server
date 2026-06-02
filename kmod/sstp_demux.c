// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * sstp_demux.c — receive data path.
 *
 * Hooks `sk_data_ready` on the kTLS-equipped TCP socket; the worker
 * drains it via `kernel_recvmsg`, reassembles [MS-SSTP] §2.2.3
 * data-packet frames out of the byte stream, allocates skbs and
 * pushes the PPP payload up via `ppp_input()`. Control-packet
 * frames (C-bit = 1) are queued and surfaced to userspace via
 * SSTP_EVT_CONTROL_PACKET + SSTP_IOC_RECV_CONTROL so the SSTP
 * state machine (hello timer, Call-Disconnect handling) stays in
 * userspace. Non-application-data TLS records (TLS 1.3 KeyUpdate,
 * NewSessionTicket) are detected via the TLS_GET_RECORD_TYPE cmsg
 * and surfaced as SSTP_EVT_TLS_REKEY_NEEDED.
 */

#include <linux/errno.h>
#include <linux/net.h>
#include <linux/ppp_defs.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <uapi/linux/tls.h>

#include "sstp_internal.h"

/*
 * LCP packet codes (RFC 1661 §5). `<linux/ppp_defs.h>` exposes
 * `CONFREQ` / `TERMREQ` / `CODEREJ` but stops short of the echo
 * codes — keep these local.
 */
#define LCP_ECHOREQ 9
#define LCP_ECHOREP 10

/* Inline LCP Echo-Request → Echo-Reply handler.
 *
 * Mainline `ppp_generic` routes any PPP frame with proto >= 0xc000
 * (LCP, PAP, CHAP, …) to the channel's read queue (`pch->file.rq`)
 * for a userspace pppd to drain. This kmod owns the channel and
 * there is no userspace pppd in the design — so without this
 * handler, LCP Echo-Requests pile up in `pch->file.rq` until they
 * hit `PPP_MAX_RQLEN` and get silently dropped. After three missed
 * replies (~3 minutes at the default `lcp-echo-interval 60`),
 * pppd-on-the-peer (Windows / sstpc) declares the link dead and
 * disconnects.
 *
 * Replying inline from the RX worker keeps the steady-state data
 * path entirely in kernel context. Build an Echo-Reply skb (RFC
 * 1661 §5.8) and queue it on `tx_q` exactly as `start_xmit`
 * would; the existing TX worker does the SSTP framing + send.
 *
 * Returns true if the frame was an LCP Echo-Request and has been
 * handled (caller must not forward it to `ppp_input`).
 */
static bool sstp_handle_lcp_echo(struct sstp_session *s, const u8 *payload, u32 payload_len)
{
	struct sk_buff *skb;
	u8 *p;
	u16 lcp_len;

	/* proto(2) + LCP code(1) + id(1) + length(2) + magic(4) */
	if (payload_len < 10)
		return false;
	if (payload[0] != (PPP_LCP >> 8) || payload[1] != (PPP_LCP & 0xff))
		return false; /* not LCP */
	if (payload[2] != LCP_ECHOREQ)
		return false; /* not Echo-Request */

	lcp_len = ((u16)payload[4] << 8) | payload[5];
	if (lcp_len < 8 || (u32)lcp_len + 2u > payload_len)
		return false; /* malformed; let ppp_input log it */

	if (READ_ONCE(s->closing))
		return true;
	if (skb_queue_len(&s->tx_q) >= SSTP_TX_Q_CAP)
		return true; /* swallow; no room to reply */

	skb = dev_alloc_skb(2 + lcp_len);
	if (!skb)
		return true; /* swallow; OOM, peer will retry */

	p = skb_put(skb, 2 + lcp_len);
	p[0] = PPP_LCP >> 8; /* PPP Protocol: LCP */
	p[1] = PPP_LCP & 0xff;
	p[2] = LCP_ECHOREP; /* Code: Echo-Reply */
	p[3] = payload[3]; /* Identifier (echo) */
	p[4] = payload[4]; /* Length (echo) */
	p[5] = payload[5];
	/* Magic-Number: zero is permitted by RFC 1661 §6.4 when
	 * Magic-Number was not negotiated for our direction. The
	 * kmod does not have visibility into the userspace LCP
	 * negotiation, so always emit zero — both Windows and
	 * sstpc accept this. */
	p[6] = 0;
	p[7] = 0;
	p[8] = 0;
	p[9] = 0;
	if (lcp_len > 8)
		memcpy(p + 10, payload + 10, lcp_len - 8);

	skb_queue_tail(&s->tx_q, skb);
	queue_work(s->wq, &s->tx_work);
	return true;
}

/* Hand a single PPP-payload skb up to ppp_generic. The wire format
 * inside an SSTP data packet is a full PPP frame with the HDLC-style
 * Address (0xff) + Control (0x03) prefix unless ACFC was negotiated
 * by LCP. The userspace driver does not propose ACFC, so peers send
 * A/C-prefixed frames. ppp_generic's channel input expects the skb
 * to start with the 2-byte Protocol field, so strip the leading
 * `ff 03` here when present. Without this the kernel parses the
 * Address byte as the high half of the protocol id and silently
 * drops every IP packet. */
static void sstp_deliver_ppp(struct sstp_session *s, const u8 *payload, u32 payload_len)
{
	struct sk_buff *skb;

	if (payload_len >= 2 && payload[0] == PPP_ALLSTATIONS && payload[1] == PPP_UI) {
		payload += 2;
		payload_len -= 2;
	}
	if (payload_len < 2) {
		atomic64_inc(&s->stats_sstp_malformed);
		return;
	}

	if (sstp_handle_lcp_echo(s, payload, payload_len))
		return;

	skb = dev_alloc_skb(payload_len);
	if (!skb) {
		atomic64_inc(&s->stats_sstp_malformed);
		return;
	}
	skb_put_data(skb, payload, payload_len);

	atomic64_inc(&s->stats_ppp_frames_rx);

	sstp_dbg("rx ppp session=%p len=%u proto=0x%02x%02x\n", s, payload_len, payload[0],
		 payload[1]);

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

	while (s->rx_len - off >= SSTP_HEADER_LEN) {
		const u8 *p = s->rx_buf + off;
		u8 ver = p[0];
		u8 c = p[1] & SSTP_C_BIT;
		u16 length = ((u16)p[2] << 8 | p[3]) & SSTP_LEN_MASK;

		if (ver != SSTP_VERSION_1_0 || length < SSTP_HEADER_LEN) {
			pr_warn_ratelimited(SSTP_MOD_NAME
					    ": bad framing v=0x%02x len=%u; aborting\n",
					    ver, length);
			atomic64_inc(&s->stats_sstp_malformed);
			sstp_session_emit(s, SSTP_EVT_PROTOCOL_ERROR, ver);
			WRITE_ONCE(s->closing, true);
			return off;
		}
		if (length > s->rx_len - off)
			break; /* need more bytes */

		atomic64_inc(&s->stats_sstp_frames_rx);

		sstp_dbg("demux session=%p c=%u len=%u\n", s, c, length);

		if (c == 0) {
			sstp_deliver_ppp(s, p + SSTP_HEADER_LEN, length - SSTP_HEADER_LEN);
		} else {
			/* Control packet (C=1): keepalives, Call-Disconnect,
			 * etc. Stash the payload and notify userspace via
			 * SSTP_EVT_CONTROL_PACKET; userspace pulls it with
			 * SSTP_IOC_RECV_CONTROL. */
			u32 plen = length - SSTP_HEADER_LEN;
			struct sk_buff *skb;
			unsigned long qflags;
			u32 next_head;
			bool enqueued = false;

			skb = dev_alloc_skb(plen);
			if (skb) {
				skb_put_data(skb, p + SSTP_HEADER_LEN, plen);
				spin_lock_irqsave(&s->ctrl_q_lock, qflags);
				next_head = (s->ctrl_q_head + 1) % SSTP_CTRL_Q_CAP;
				if (next_head != s->ctrl_q_tail) {
					s->ctrl_q[s->ctrl_q_head] = skb;
					s->ctrl_q_head = next_head;
					enqueued = true;
				}
				spin_unlock_irqrestore(&s->ctrl_q_lock, qflags);
			}
			if (!enqueued) {
				if (skb)
					kfree_skb(skb);
				atomic64_inc(&s->stats_sstp_malformed);
				pr_warn_ratelimited(SSTP_MOD_NAME ": control queue overflow; "
								  "dropped frame (len=%u)\n",
						    length);
			} else {
				atomic64_inc(&s->stats_ctrl_frames_rx);
				sstp_session_emit(s, SSTP_EVT_CONTROL_PACKET, plen);
			}
		}
		off += length;
	}

	return off;
}

/* Drain the socket once. Returns the number of bytes received, or a
 * negative errno (with -EAGAIN meaning "no more data right now"). */
static int sstp_demux_recv_once(struct sstp_session *s)
{
	union {
		struct cmsghdr hdr;
		u8 buf[CMSG_SPACE(sizeof(u8))];
	} cmsg;
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
		.msg_control = &cmsg,
		.msg_controllen = sizeof(cmsg),
	};
	struct kvec iov;
	struct cmsghdr *c;
	int ret;

	if (s->rx_len >= SSTP_RX_BUF_CAP)
		return -ENOBUFS;

	/* Zero the cmsg backing buffer so CMSG_NXTHDR terminates
	 * correctly when the kernel returns no ancillary data. With
	 * an uninitialised cmsg_len of 0, CMSG_NXTHDR's "advance by
	 * CMSG_ALIGN(cmsg_len)" arithmetic returns the same pointer
	 * and the walk loops forever (soft lockup). Zeroing forces
	 * cmsg_len = 0 so our `c->cmsg_len < sizeof(*c)` guard below
	 * trips on the first (garbage) header. */
	memset(&cmsg, 0, sizeof(cmsg));

	iov.iov_base = s->rx_buf + s->rx_len;
	iov.iov_len = SSTP_RX_BUF_CAP - s->rx_len;

	ret = kernel_recvmsg(s->tcp_sock, &msg, &iov, 1, iov.iov_len, MSG_DONTWAIT);

	/* kTLS: any cmsg present means a non-application_data record
	 * was returned. Post-attach the only legitimate case is a
	 * TLS 1.3 post-handshake message (KeyUpdate, NewSessionTicket).
	 * The kmod can't decrypt across a KeyUpdate without userspace
	 * re-installing crypto, so signal and pause. */
	for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
		if (c->cmsg_len < sizeof(*c))
			break;
		if (c->cmsg_level == SOL_TLS && c->cmsg_type == TLS_GET_RECORD_TYPE) {
			u8 rt = *(u8 *)CMSG_DATA(c);

			pr_info(SSTP_MOD_NAME ": non-app-data TLS record type=%u; "
					      "signalling REKEY_NEEDED\n",
				rt);
			sstp_session_emit(s, SSTP_EVT_TLS_REKEY_NEEDED, rt);
			WRITE_ONCE(s->closing, true);
			return -EPIPE;
		}
	}

	if (ret > 0) {
		s->rx_len += ret;
		atomic64_inc(&s->stats_tls_records_rx);
		sstp_dbg("recv session=%p bytes=%d rx_len=%u\n", s, ret, s->rx_len);
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
			if (rc == -EPIPE) {
				/* REKEY_NEEDED already emitted; closing
				 * is already set. Exit quietly. */
				break;
			}
			pr_warn_ratelimited(SSTP_MOD_NAME ": recv error %d; aborting session\n",
					    rc);
			sstp_session_emit(s, SSTP_EVT_TLS_FATAL_ALERT, (u32)-rc);
			WRITE_ONCE(s->closing, true);
			break;
		}

		if (s->rx_len) {
			u32 consumed = sstp_demux_parse(s);

			if (consumed) {
				s->rx_len -= consumed;
				/* Common case: the buffer drained completely
				 * (every received chunk parsed cleanly into
				 * full SSTP frames). Skipping the memmove of
				 * zero bytes is free; doing so for the
				 * straddling-frame remainder keeps the slow
				 * path bounded by the leftover header + body
				 * (< SSTP_MAX_PACKET_LEN). */
				if (s->rx_len)
					memmove(s->rx_buf, s->rx_buf + consumed, s->rx_len);
			}
		}

		/* Bound per-wakeup work so we don't starve the workqueue.
		 * The cap is in `kernel_recvmsg` calls; each call drains
		 * up to SSTP_RX_BUF_CAP - rx_len bytes and produces many
		 * SSTP frames, so a higher bound here directly reduces
		 * workqueue requeue overhead under sustained load. */
		if (++loops >= 64) {
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

/*
 * sk_write_space hook: socket buffer drained below the wakeup
 * watermark. Runs in softirq context, where we cannot safely
 * call `kernel_sendmsg()` (sleepable) or re-enter the channel's
 * `start_xmit` (atomic-locked). Just kick the TX worker; it will
 * drain `tx_q` in process context and call `ppp_output_wakeup()`
 * if it makes room for skbs `ppp_generic` is holding.
 */
static void sstp_sk_write_space(struct sock *sk)
{
	struct sstp_session *s = sk->sk_user_data;

	if (likely(s) && !READ_ONCE(s->closing)) {
		queue_work(s->wq, &s->tx_work);
		/* Wake any poll(session_fd) waiter so SSTP_IOC_SEND_CONTROL
		 * callers can retry after -EAGAIN. */
		wake_up_interruptible_poll(&s->tx_wait, EPOLLOUT | EPOLLWRNORM);
	}

	/* Chain to the original handler so anything else still
	 * listening (e.g. epoll EPOLLOUT) sees the wakeup. */
	if (s && s->saved_write_space)
		s->saved_write_space(sk);
}

void sstp_demux_install_callback(struct sstp_session *s)
{
	struct sock *sk = s->tcp_sock->sk;

	write_lock_bh(&sk->sk_callback_lock);
	s->saved_data_ready = sk->sk_data_ready;
	s->saved_write_space = sk->sk_write_space;
	s->saved_user_data = sk->sk_user_data;
	sk->sk_user_data = s;
	sk->sk_data_ready = sstp_sk_data_ready;
	sk->sk_write_space = sstp_sk_write_space;
	s->cb_installed = true;
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
	sk->sk_write_space = s->saved_write_space;
	sk->sk_user_data = s->saved_user_data;
	s->cb_installed = false;
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

	/* Synchronous cancel of both work items; if either is queued
	 * or running, this waits for it. After both return, neither
	 * worker will touch the session again. */
	cancel_work_sync(&s->rx_work);
	cancel_work_sync(&s->tx_work);

	/* Drop any skbs ppp_generic handed us that we never got
	 * around to sending. */
	skb_queue_purge(&s->tx_q);

	if (s->wq)
		flush_workqueue(s->wq);
}
