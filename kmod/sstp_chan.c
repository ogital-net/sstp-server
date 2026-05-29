// SPDX-License-Identifier: GPL-2.0
/*
 * sstp_chan.c — `struct ppp_channel` ops.
 *
 * ppp_generic calls into us with PPP frames on the TX path (peer
 * direction). We wrap them in SSTP framing ([MS-SSTP] §2.2.3),
 * encrypt via kTLS (handled transparently by sendmsg on the
 * kTLS-equipped socket), and push to the wire.
 *
 * v0.1 status: TX path is stubbed. start_xmit returns 1 (consumed)
 * after dropping the skb; the real implementation lives behind the
 * TODO below.
 */

#include <linux/errno.h>
#include <linux/ppp_channel.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include "sstp_internal.h"

static int sstp_chan_start_xmit(struct ppp_channel *chan,
				struct sk_buff *skb)
{
	struct sstp_session *s = chan->private;
	unsigned long flags;

	/* TODO(v0.1): SSTP-encapsulate (§2.2.3 data packet header:
	 * version, R-bit, length), then kernel_sendmsg() on
	 * s->tcp_sock. kTLS handles the AEAD seal transparently.
	 *
	 * For the draft we drop the frame but bump the counter so
	 * a loadable build is observable. Returning 1 tells
	 * ppp_generic the frame was consumed (don't queue). */
	spin_lock_irqsave(&s->stats_lock, flags);
	s->stats.ppp_frames_tx++;
	spin_unlock_irqrestore(&s->stats_lock, flags);

	kfree_skb(skb);
	return 1;
}

static int sstp_chan_ioctl(struct ppp_channel *chan, unsigned int cmd,
			   unsigned long arg)
{
	(void)chan;
	(void)cmd;
	(void)arg;

	/* No channel-specific ioctls in v0.1; everything goes through
	 * the session_fd. */
	return -ENOTTY;
}

const struct ppp_channel_ops sstp_chan_ops = {
	.start_xmit = sstp_chan_start_xmit,
	.ioctl      = sstp_chan_ioctl,
};
