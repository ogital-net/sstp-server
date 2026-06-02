// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * sstp_main.c — module entry, /dev/sstp misc device, top-level
 *               ioctl dispatch.
 *
 * The misc device is the single user-visible entry point. The
 * actual session lives on an anon_inode fd returned via
 * SSTP_IOC_ATTACH; the misc fd itself carries no per-open state
 * beyond CAP checks and the attach dispatch.
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>

#include "sstp_internal.h"

/* /dev/sstp permission bits. Default 0600 matches the kernel's
 * convention for privileged misc devices. Operators that run
 * sstp-server under a dropped uid can load with `mode=0660` (or
 * `mode=0666` for development) and use a udev rule to set the
 * group, e.g.:
 *
 *   KERNEL=="sstp", MODE="0660", GROUP="sstp"
 *
 * dropped to /etc/udev/rules.d/. */
static ushort sstp_dev_mode = 0600;
module_param_named(mode, sstp_dev_mode, ushort, 0444);
MODULE_PARM_DESC(mode, "permission bits for /dev/sstp (default 0600)");

static long sstp_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SSTP_IOC_ATTACH:
		/* CAP_NET_ADMIN, but namespaced: a container running as
		 * root in its own user namespace with NET_ADMIN granted
		 * (Docker `--cap-add=NET_ADMIN` under userns-remap,
		 * rootless Podman, k8s securityContext) legitimately
		 * holds the cap over its own netns even though the
		 * unnamespaced `capable()` check would refuse.
		 *
		 * The TCP socket the caller hands us is resolved against
		 * its own fdtable in `sstp_do_attach`, and
		 * `ppp_register_channel()` registers in
		 * `current->nsproxy->net_ns`, so the rest of the
		 * attach path is already namespace-correct. */
		if (!ns_capable(current_user_ns(), CAP_NET_ADMIN))
			return -EPERM;
		return sstp_do_attach(file, (struct sstp_attach __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations sstp_misc_fops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.unlocked_ioctl = sstp_misc_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice sstp_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = SSTP_DEVICE_NAME,
	.fops = &sstp_misc_fops,
	.mode = 0600,
};

static int __init sstp_init(void)
{
	int ret;

	sstp_misc_dev.mode = sstp_dev_mode;

	ret = misc_register(&sstp_misc_dev);
	if (ret) {
		pr_err(SSTP_MOD_NAME ": misc_register failed: %d\n", ret);
		return ret;
	}

	pr_info(SSTP_MOD_NAME ": loaded (ABI %u.%u, mode=0%o)\n", SSTP_ABI_VERSION_MAJOR,
		SSTP_ABI_VERSION_MINOR, sstp_dev_mode);
	return 0;
}

static void __exit sstp_exit(void)
{
	misc_deregister(&sstp_misc_dev);
	pr_info(SSTP_MOD_NAME ": unloaded\n");
}

module_init(sstp_init);
module_exit(sstp_exit);

MODULE_AUTHOR("Latigo LLC");
MODULE_DESCRIPTION("SSTP (MS-SSTP) PPP channel driver");
/* Dual BSD/GPL: the kernel sees a GPL-compatible license so we
 * can link against GPL-only kernel symbols (kTLS, anon_inode,
 * tracepoints), while the source is also redistributable under
 * BSD-2-Clause to match the rest of the project. See the SPDX
 * tag at the top of each source file. */
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1.0");
MODULE_ALIAS("devname:" SSTP_DEVICE_NAME);
