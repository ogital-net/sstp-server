// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * sstp_attach.c — SSTP_IOC_ATTACH implementation.
 *
 * Validates the userspace handoff (kTLS-equipped TCP fd + PPP unit
 * number), registers a PPP channel, and returns a session_fd that
 * owns the channel's lifetime.
 */

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/compiler_attributes.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
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

	sstp_dbg("release session=%p chan_registered=%d\n", s, s->chan_registered);

	if (s->chan_registered)
		ppp_unregister_channel(&s->chan);

	if (s->wq)
		destroy_workqueue(s->wq);

	kfree(s->rx_buf);

	/* Drop any control packets userspace never drained. */
	while (s->ctrl_q_head != s->ctrl_q_tail) {
		kfree_skb(s->ctrl_q[s->ctrl_q_tail]);
		s->ctrl_q_tail = (s->ctrl_q_tail + 1) % SSTP_CTRL_Q_CAP;
	}

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

long sstp_do_attach(struct file *misc_file __maybe_unused, struct sstp_attach __user *uarg)
{
	struct sstp_attach a;
	struct sstp_session *s = NULL;
	struct file *session_file = NULL;
	struct socket *tcp_sock = NULL;
	int session_fd = -1;
	int ret;

	if (copy_from_user(&a, uarg, sizeof(a)))
		return -EFAULT;

	if (a.abi_major != SSTP_ABI_VERSION_MAJOR)
		return -EINVAL;
	if (a.tcp_fd < 0)
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	kref_init(&s->ref);
	spin_lock_init(&s->evt_lock);
	spin_lock_init(&s->ctrl_q_lock);
	init_waitqueue_head(&s->evt_wait);
	init_waitqueue_head(&s->tx_wait);
	mutex_init(&s->close_lock);
	INIT_WORK(&s->rx_work, sstp_rx_worker);
	INIT_WORK(&s->tx_work, sstp_tx_worker);
	skb_queue_head_init(&s->tx_q);
	s->mtu = a.mtu ? a.mtu : 1500;

	s->rx_buf = kmalloc(SSTP_RX_BUF_CAP, GFP_KERNEL);
	if (!s->rx_buf) {
		ret = -ENOMEM;
		goto err_free;
	}

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

	/* PPP channel ops. The kernel registers a channel only; the
	 * unit binding is owned by userspace, which calls
	 * `PPPIOCATTCHAN` + `PPPIOCCONNECT` on its own /dev/ppp handle
	 * with the channel index returned by SSTP_IOC_GET_CHAN_INDEX. */
	s->chan.private = s;
	s->chan.ops = &sstp_chan_ops;
	s->chan.mtu = s->mtu;
	/* hdrlen is the headroom ppp_generic reserves on outbound skbs
	 * so a channel can `skb_push` its framing inline. We do *not*
	 * push — the SSTP 4-byte header is sent as a separate kvec in
	 * `kernel_sendmsg` — so 0 is the honest answer. */
	s->chan.hdrlen = 0;

	ret = ppp_register_channel(&s->chan);
	if (ret)
		goto err_free;
	s->chan_registered = true;

	/* Per-session unbound workqueue. Hosts both `rx_work` (kTLS
	 * drain + SSTP demux + `ppp_input()`) and `tx_work` (drain
	 * `tx_q` + `kernel_sendmsg()`). Each work_struct is
	 * implicitly serialised against itself by the workqueue
	 * pending bit, which is what preserves PPP packet order on
	 * RX and TX independently. We deliberately do *not* use an
	 * ordered workqueue: cross-rx/tx ordering is not required,
	 * and forcing it serialises TCP ACK transmission (TX) behind
	 * batched RX demux loops, capping bidirectional throughput.
	 * `WQ_UNBOUND` lets the worker thread pool pick whichever
	 * CPU is idle; with `max_active = 2` rx_work and tx_work
	 * can run concurrently on different CPUs while neither
	 * worker overlaps itself. Per-session granularity still
	 * gives N concurrent sessions N independent pipelines. */
	s->wq = alloc_workqueue("sstp/%d", WQ_UNBOUND | WQ_MEM_RECLAIM, 2,
				ppp_channel_index(&s->chan));
	if (!s->wq) {
		ret = -ENOMEM;
		goto err_free;
	}

	/* Anon-inode fd for the session. The caller's userspace will
	 * poll/read/ioctl this fd; closing it triggers detach via
	 * sstp_session_fops.release. The file inherits the kref_init
	 * reference; on success we hand it off and return without
	 * an explicit put. On failure below the err_free path puts
	 * that reference and runs the kref release callback. */
	session_fd = get_unused_fd_flags(O_CLOEXEC);
	if (session_fd < 0) {
		ret = session_fd;
		goto err_free;
	}

	session_file =
		anon_inode_getfile("[sstp-session]", &sstp_session_fops, s, O_RDWR | O_CLOEXEC);
	if (IS_ERR(session_file)) {
		ret = PTR_ERR(session_file);
		put_unused_fd(session_fd);
		goto err_free;
	}

	fd_install(session_fd, session_file);
	a.session_fd = session_fd;
	/* Echo our minor back to userspace so the caller can gate
	 * optional features once 0.x grows them. */
	a.abi_minor = SSTP_ABI_VERSION_MINOR;
	if (copy_to_user(uarg, &a, sizeof(a))) {
		/* Userspace pointer turned bad between copy_from_user
		 * and now. Roll back the install: we still own the
		 * primary kref via the file. close_fd() drops the
		 * file ref synchronously which triggers
		 * sstp_session_release(); no leak. */
		close_fd(session_fd);
		return -EFAULT;
	}

	/* Wire the socket callback last — after this, sstp_sk_data_ready
	 * may fire on any new bytes and queue rx_work. The work item
	 * holds an implicit reference via being queued; the demux
	 * shutdown path cancels it before the final put. */
	sstp_demux_install_callback(s);

	/* Kick off the receive loop in case bytes were already queued
	 * before the callback was installed. */
	queue_work(s->wq, &s->rx_work);

	sstp_dbg("attach session=%p chan=%d mtu=%u tcp_fd=%d session_fd=%d\n", s,
		 ppp_channel_index(&s->chan), s->mtu, a.tcp_fd, session_fd);

	return 0;

err_free:
	sstp_session_put(s);
	return ret;
}
