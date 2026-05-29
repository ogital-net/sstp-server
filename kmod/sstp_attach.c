// SPDX-License-Identifier: GPL-2.0
/*
 * sstp_attach.c — SSTP_IOC_ATTACH implementation.
 *
 * Validates the userspace handoff (kTLS-equipped TCP fd + PPP unit
 * number), registers a PPP channel, and returns a session_fd that
 * owns the channel's lifetime.
 */

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tls.h>

#include "sstp_internal.h"

static void sstp_session_release(struct kref *ref)
{
	struct sstp_session *s = container_of(ref, struct sstp_session, ref);

	if (s->chan_registered)
		ppp_unregister_channel(&s->chan);

	if (s->wq)
		destroy_workqueue(s->wq);

	if (s->tcp_file)
		fput(s->tcp_file);

	mutex_destroy(&s->close_lock);
	kfree(s);
}

void sstp_session_get(struct sstp_session *s)
{
	kref_get(&s->ref);
}

void sstp_session_put(struct sstp_session *s)
{
	kref_put(&s->ref, sstp_session_release);
}

/*
 * Confirm the supplied fd is a TCP stream socket with kTLS RX and
 * TX crypto installed. We do not (cannot) verify the TLS handshake
 * is actually finished — that is the userspace TLS library's
 * contract. We only check that the ULP layer has populated the
 * TLS context with both directions configured.
 */
static int sstp_validate_ktls(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct tls_context *tls;

	if (!sk)
		return -EINVAL;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
		return -EAFNOSUPPORT;
	if (sock->type != SOCK_STREAM)
		return -EPROTONOSUPPORT;
	if (sk->sk_protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;

	tls = tls_get_ctx(sk);
	if (!tls)
		return -EOPNOTSUPP;

	/* Both directions must be configured (anything other than
	 * TLS_BASE). We accept either TLS_SW or TLS_HW; the kernel
	 * path is the same from the SSTP demux's perspective. */
	if (tls->tx_conf == TLS_BASE || tls->rx_conf == TLS_BASE)
		return -EOPNOTSUPP;

	return 0;
}

long sstp_do_attach(struct file *misc_file,
		    struct sstp_attach __user *uarg)
{
	struct sstp_attach a;
	struct sstp_session *s = NULL;
	struct file *session_file = NULL;
	struct socket *tcp_sock = NULL;
	int session_fd = -1;
	int ret;

	(void)misc_file;

	if (copy_from_user(&a, uarg, sizeof(a)))
		return -EFAULT;

	if (a.abi_major != SSTP_ABI_VERSION_MAJOR)
		return -EINVAL;
	if (a.reserved[0] || a.reserved[1] ||
	    a.reserved[2] || a.reserved[3])
		return -EINVAL;
	if (a.tcp_fd < 0 || a.ppp_unit < 0)
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	kref_init(&s->ref);
	spin_lock_init(&s->stats_lock);
	spin_lock_init(&s->evt_lock);
	init_waitqueue_head(&s->evt_wait);
	mutex_init(&s->close_lock);
	INIT_WORK(&s->rx_work, sstp_rx_worker);
	s->ppp_unit = a.ppp_unit;
	s->flags = a.flags;
	s->mtu = a.mtu ? a.mtu : 1500;

	/* Grab the TCP fd. We take a counted reference on the
	 * underlying `struct file` so the caller can close its
	 * descriptor freely after the ioctl returns. */
	s->tcp_file = fget(a.tcp_fd);
	if (!s->tcp_file) {
		ret = -EBADF;
		goto err_free;
	}

	tcp_sock = sock_from_file(s->tcp_file);
	if (!tcp_sock) {
		ret = -ENOTSOCK;
		goto err_free;
	}
	s->tcp_sock = tcp_sock;

	ret = sstp_validate_ktls(tcp_sock);
	if (ret)
		goto err_free;

	/* PPP channel ops. We don't bind to a specific unit number
	 * here — userspace will issue PPPIOCATTCHAN/PPPIOCCONNECT on
	 * its own /dev/ppp handle using the channel number we expose
	 * via SSTP_IOC_GETSTATS (TODO: separate ioctl). */
	s->chan.private = s;
	s->chan.ops = &sstp_chan_ops;
	s->chan.mtu = s->mtu;
	s->chan.hdrlen = 2; /* PPP protocol id; SSTP framing is added below */

	ret = ppp_register_channel(&s->chan);
	if (ret)
		goto err_free;
	s->chan_registered = true;

	/* Workqueue for the receive path. Single-threaded so the
	 * SSTP demux state machine doesn't need its own lock against
	 * itself; ordering vs. start_xmit is enforced by ppp_generic. */
	s->wq = alloc_ordered_workqueue("sstp-rx/%d",
					WQ_MEM_RECLAIM,
					ppp_channel_index(&s->chan));
	if (!s->wq) {
		ret = -ENOMEM;
		goto err_free;
	}

	/* Anon-inode fd for the session. The caller's userspace will
	 * poll/read/ioctl this fd; closing it triggers detach via
	 * sstp_session_fops.release. */
	session_fd = get_unused_fd_flags(O_CLOEXEC);
	if (session_fd < 0) {
		ret = session_fd;
		goto err_free;
	}

	sstp_session_get(s); /* file holds a reference */
	session_file = anon_inode_getfile("[sstp-session]",
					  &sstp_session_fops, s,
					  O_RDWR | O_CLOEXEC);
	if (IS_ERR(session_file)) {
		ret = PTR_ERR(session_file);
		sstp_session_put(s);
		put_unused_fd(session_fd);
		goto err_free;
	}

	fd_install(session_fd, session_file);
	a.session_fd = session_fd;
	if (copy_to_user(uarg, &a, sizeof(a))) {
		/* User vanished between the copy_from_user and now. The
		 * fd is already installed; the safe thing is to let the
		 * caller observe the install via close-on-exit and we
		 * return -EFAULT. The session keeps running until they
		 * close the fd. */
		return -EFAULT;
	}

	/* Kick off the receive loop. The work item holds its own
	 * implicit reference via being queued; sstp_demux_shutdown()
	 * cancels and waits before final put. */
	queue_work(s->wq, &s->rx_work);

	return 0;

err_free:
	sstp_session_put(s);
	return ret;
}
