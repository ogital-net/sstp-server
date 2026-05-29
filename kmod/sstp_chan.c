// SPDX-License-Identifier: GPL-2.0
/*
 * sstp_chan.c — `struct ppp_channel` ops (TX path).
 *
 * ppp_generic invokes start_xmit with PPP frames bound for the
 * peer. We prepend the 4-byte SSTP data-packet header
 * ([MS-SSTP] §2.2.3) and push the result down the kTLS socket;
 * kTLS handles the AEAD seal transparently.
 */

#include <linux/errno.h>
#include <linux/net.h>
#include <linux/ppp_channel.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uio.h>
#include <net/sock.h>

#include "sstp_internal.h"

static int sstp_chan_start_xmit(struct ppp_channel *chan,
				struct sk_buff *skb)
{
	struct sstp_session *s = chan->private;
	u8 hdr[SSTP_HEADER_LEN + 2];
	struct kvec iov[2];
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	/* ppp_generic hands us the PPP frame starting at the 2-byte
	 * Protocol field; the peer expects the HDLC-style Address +
	 * Control prefix because ACFC was not negotiated by LCP. We
	 * fold both the SSTP header and the `ff 03` A/C bytes into a
	 * single 6-byte prefix iovec so this stays a one-syscall send. */
	size_t total = SSTP_HEADER_LEN + 2 + skb->len;
	int ret;

	if (READ_ONCE(s->closing)) {
		kfree_skb(skb);
		return 1;
	}
	if (total > SSTP_MAX_PACKET_LEN) {
		/* Larger than what the 12-bit Length field can carry.
		 * ppp_generic enforces MRU but defence in depth. */
		atomic64_inc(&s->stats_sstp_malformed);
		kfree_skb(skb);
		return 1;
	}

	/* [MS-SSTP] §2.2.3 data-packet header. */
	hdr[0] = SSTP_VERSION_1_0;
	hdr[1] = 0;                       /* C = 0 (data), Reserved = 0 */
	hdr[2] = (total >> 8) & 0x0F;     /* R (4 bits) = 0 | high nibble */
	hdr[3] = total & 0xFF;
	hdr[4] = 0xff;                    /* PPP Address (all-stations) */
	hdr[5] = 0x03;                    /* PPP Control (UI) */

	iov[0].iov_base = hdr;
	iov[0].iov_len  = SSTP_HEADER_LEN + 2;
	iov[1].iov_base = skb->data;
	iov[1].iov_len  = skb->len;

	ret = kernel_sendmsg(s->tcp_sock, &msg, iov, 2, total);

	if (ret == (int)total) {
		atomic64_inc(&s->stats_ppp_frames_tx);
		atomic64_inc(&s->stats_sstp_frames_tx);
		atomic64_inc(&s->stats_tls_records_tx);
		kfree_skb(skb);
		return 1;
	}

	if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
		/* Socket buffer full. Tell ppp_generic to hold off by
		 * returning 0; the skb stays queued at the channel and
		 * ppp_generic will re-call us once ppp_output_wakeup()
		 * fires from the sk_write_space hook installed in
		 * sstp_demux_install_callback(). */
		return 0;
	}

	/* Short write or hard error: the TCP stream is now ambiguous
	 * (the kernel may have buffered the header but not the body,
	 * or vice versa). Tear the session down — there is no clean
	 * resync. */
	pr_warn_ratelimited(SSTP_MOD_NAME
		": sendmsg ret=%d (wanted %zu); aborting session\n",
		ret, total);
	sstp_session_emit(s, SSTP_EVT_TLS_FATAL_ALERT,
			  ret < 0 ? (u32)-ret : 0);
	WRITE_ONCE(s->closing, true);
	kfree_skb(skb);
	return 1;
}

static int sstp_chan_ioctl(struct ppp_channel *chan, unsigned int cmd,
			   unsigned long arg)
{
	(void)chan;
	(void)cmd;
	(void)arg;

	/* No channel-specific ioctls — everything goes through the
	 * session_fd. */
	return -ENOTTY;
}

const struct ppp_channel_ops sstp_chan_ops = {
	.start_xmit = sstp_chan_start_xmit,
	.ioctl      = sstp_chan_ioctl,
};
