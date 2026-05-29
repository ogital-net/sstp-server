// SPDX-License-Identifier: GPL-2.0
/*
 * sstp_event.c — file_operations for the session_fd.
 *
 * Userspace polls/reads this fd to learn about exceptional
 * conditions (peer close, TLS fatal alert, kTLS rekey needed,
 * protocol error). Closing it triggers detach.
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "sstp_internal.h"

/*
 * Enqueue a new event for userspace. Per-type coalescing: if the
 * ring is full we increment `stats_evt_dropped` and overwrite the
 * most recent slot with the same type. Events are advisory; we never
 * block the data path on a slow reader.
 */
void sstp_session_emit(struct sstp_session *s, u32 type, u32 arg)
{
	unsigned long flags;
	struct sstp_event *e;
	u32 next_head;

	spin_lock_irqsave(&s->evt_lock, flags);
	next_head = (s->evt_head + 1) % SSTP_EVENT_QUEUE_CAP;
	if (next_head == s->evt_tail) {
		/* Ring full; overwrite the slot just behind head if it
		 * matches `type`, else bump the drop counter. */
		u32 prev = (s->evt_head + SSTP_EVENT_QUEUE_CAP - 1) %
			   SSTP_EVENT_QUEUE_CAP;
		if (s->evt_head != s->evt_tail &&
		    s->events[prev].type == type) {
			s->events[prev].arg = arg;
			s->events[prev].timestamp_ns =
				ktime_get_ns();
		}
		spin_unlock_irqrestore(&s->evt_lock, flags);
		atomic64_inc(&s->stats_evt_dropped);
		return;
	}

	e = &s->events[s->evt_head];
	e->type = type;
	e->arg = arg;
	e->timestamp_ns = ktime_get_ns();
	s->evt_head = next_head;
	spin_unlock_irqrestore(&s->evt_lock, flags);

	wake_up_interruptible(&s->evt_wait);
}

static ssize_t sstp_session_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct sstp_session *s = file->private_data;
	struct sstp_event e;
	unsigned long flags;
	int ret;

	if (count < sizeof(struct sstp_event))
		return -EINVAL;

	for (;;) {
		spin_lock_irqsave(&s->evt_lock, flags);
		if (s->evt_head != s->evt_tail) {
			e = s->events[s->evt_tail];
			s->evt_tail = (s->evt_tail + 1) %
				      SSTP_EVENT_QUEUE_CAP;
			spin_unlock_irqrestore(&s->evt_lock, flags);
			break;
		}
		spin_unlock_irqrestore(&s->evt_lock, flags);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(
			s->evt_wait, s->evt_head != s->evt_tail || s->closing);
		if (ret)
			return ret;
		if (s->closing)
			return 0;
	}

	if (copy_to_user(buf, &e, sizeof(e)))
		return -EFAULT;

	*ppos += sizeof(e);
	return sizeof(e);
}

static __poll_t sstp_session_poll(struct file *file,
				  struct poll_table_struct *wait)
{
	struct sstp_session *s = file->private_data;
	__poll_t mask = 0;
	unsigned long flags;

	poll_wait(file, &s->evt_wait, wait);

	spin_lock_irqsave(&s->evt_lock, flags);
	if (s->evt_head != s->evt_tail)
		mask |= EPOLLIN | EPOLLRDNORM;
	spin_unlock_irqrestore(&s->evt_lock, flags);

	if (s->closing)
		mask |= EPOLLHUP;

	return mask;
}

static long sstp_session_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct sstp_session *s = file->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case SSTP_IOC_DETACH: {
		/* `_IO` ioctl — no payload. */
		(void)uarg;
		/* Mark closing; the rx worker observes this and exits
		 * its loop. The actual teardown happens on release(). */
		mutex_lock(&s->close_lock);
		s->closing = true;
		mutex_unlock(&s->close_lock);
		wake_up_interruptible(&s->evt_wait);
		return 0;
	}
	case SSTP_IOC_GETSTATS: {
		struct sstp_stats out;

		out.tls_records_rx     = atomic64_read(&s->stats_tls_records_rx);
		out.tls_records_tx     = atomic64_read(&s->stats_tls_records_tx);
		out.tls_decrypt_errors = atomic64_read(&s->stats_tls_decrypt_errors);
		out.sstp_frames_rx     = atomic64_read(&s->stats_sstp_frames_rx);
		out.sstp_frames_tx     = atomic64_read(&s->stats_sstp_frames_tx);
		out.sstp_malformed     = atomic64_read(&s->stats_sstp_malformed);
		out.ppp_frames_rx      = atomic64_read(&s->stats_ppp_frames_rx);
		out.ppp_frames_tx      = atomic64_read(&s->stats_ppp_frames_tx);
		out.evt_dropped        = atomic64_read(&s->stats_evt_dropped);

		if (copy_to_user(uarg, &out, sizeof(out)))
			return -EFAULT;
		return 0;
	}
	case SSTP_IOC_GET_CHAN_INDEX: {
		__s32 idx;

		if (!s->chan_registered)
			return -ENXIO;
		idx = ppp_channel_index(&s->chan);
		if (copy_to_user(uarg, &idx, sizeof(idx)))
			return -EFAULT;
		return 0;
	}
	case SSTP_IOC_RECV_CONTROL: {
		struct sstp_recv_control rc;
		struct sk_buff *skb = NULL;
		unsigned long flags;
		void __user *ubuf;
		u32 plen;

		if (copy_from_user(&rc, uarg, sizeof(rc)))
			return -EFAULT;

		spin_lock_irqsave(&s->ctrl_q_lock, flags);
		if (s->ctrl_q_head != s->ctrl_q_tail) {
			skb = s->ctrl_q[s->ctrl_q_tail];
			s->ctrl_q[s->ctrl_q_tail] = NULL;
			s->ctrl_q_tail = (s->ctrl_q_tail + 1) %
					 SSTP_CTRL_Q_CAP;
		}
		spin_unlock_irqrestore(&s->ctrl_q_lock, flags);

		if (!skb) {
			rc.payload_len = 0;
			if (copy_to_user(uarg, &rc, sizeof(rc)))
				return -EFAULT;
			return 0;
		}

		plen = skb->len;
		if (rc.buf_len < plen) {
			/* User passed a too-small buffer. The frame is
			 * already off the queue and there is no safe
			 * place to put it back without breaking ordering
			 * (a head-side requeue would shuffle it in front
			 * of newer frames). Drop it and bump the
			 * malformed counter so operators notice. The
			 * caller's contract is to size the buffer at
			 * SSTP_CONTROL_MAX. */
			kfree_skb(skb);
			atomic64_inc(&s->stats_sstp_malformed);
			return -EMSGSIZE;
		}

		ubuf = (void __user *)(uintptr_t)rc.buf;
		if (copy_to_user(ubuf, skb->data, plen)) {
			kfree_skb(skb);
			return -EFAULT;
		}
		kfree_skb(skb);

		rc.payload_len = plen;
		if (copy_to_user(uarg, &rc, sizeof(rc)))
			return -EFAULT;
		return plen;
	}
	default:
		return -ENOTTY;
	}
}

static int sstp_session_release(struct inode *inode, struct file *file)
{
	struct sstp_session *s = file->private_data;

	(void)inode;

	mutex_lock(&s->close_lock);
	s->closing = true;
	mutex_unlock(&s->close_lock);

	sstp_demux_shutdown(s);
	sstp_session_put(s);
	return 0;
}

const struct file_operations sstp_session_fops = {
	.owner          = THIS_MODULE,
	.read           = sstp_session_read,
	.poll           = sstp_session_poll,
	.unlocked_ioctl = sstp_session_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.release        = sstp_session_release,
};
