// SPDX-License-Identifier: GPL-2.0
/*
 * sstp_main.c — module entry, /dev/sstp misc device, top-level
 *               ioctl dispatch.
 *
 * The misc device is the single user-visible entry point. The
 * actual session lives on an anon_inode fd returned via
 * SSTP_IOC_ATTACH; the misc fd itself carries no per-open state
 * beyond CAP checks and the attach dispatch.
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/uaccess.h>

#include "sstp_internal.h"

static long sstp_misc_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case SSTP_IOC_ATTACH:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return sstp_do_attach(file,
				      (struct sstp_attach __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations sstp_misc_fops = {
	.owner          = THIS_MODULE,
	.open           = nonseekable_open,
	.unlocked_ioctl = sstp_misc_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
};

static struct miscdevice sstp_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = SSTP_DEVICE_NAME,
	.fops  = &sstp_misc_fops,
	.mode  = 0600,
};

static int __init sstp_init(void)
{
	int ret;

	ret = misc_register(&sstp_misc_dev);
	if (ret) {
		pr_err(SSTP_MOD_NAME ": misc_register failed: %d\n", ret);
		return ret;
	}

	pr_info(SSTP_MOD_NAME ": loaded (ABI %u.%u)\n",
		SSTP_ABI_VERSION_MAJOR, SSTP_ABI_VERSION_MINOR);
	return 0;
}

static void __exit sstp_exit(void)
{
	misc_deregister(&sstp_misc_dev);
	pr_info(SSTP_MOD_NAME ": unloaded\n");
}

module_init(sstp_init);
module_exit(sstp_exit);

MODULE_AUTHOR("ogital");
MODULE_DESCRIPTION("SSTP (MS-SSTP) PPP channel driver — v0.1 draft");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0-draft");
MODULE_ALIAS("devname:" SSTP_DEVICE_NAME);
