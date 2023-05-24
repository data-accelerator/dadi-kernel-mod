// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include "dm-ovbd.h"

static struct ovbd_context global_ovbd_context;

static int __init init_ovbd_target(void)
{
	global_ovbd_context.wq =
		alloc_workqueue("ovbd", WQ_MEM_RECLAIM | WQ_FREEZABLE | WQ_UNBOUND, 0);
	if (IS_ERR(global_ovbd_context.wq))
		return -1;
	if (init_lsmt_target() < 0)
		goto error_out;
	if (init_zfile_target() < 0)
		goto error_out;
	pr_info("OVBD initialized");
	return 0;
error_out:
	destroy_workqueue(global_ovbd_context.wq);
	return -1;
}

static void __exit cleanup_ovbd_target(void)
{
	cleanup_zfile_target();
	cleanup_lsmt_target();
	flush_workqueue(global_ovbd_context.wq);
	destroy_workqueue(global_ovbd_context.wq);
	global_ovbd_context.wq = NULL;
	pr_info("OVBD cleared");
}

struct ovbd_context *get_ovbd_context(void)
{
	return &global_ovbd_context;
}

module_init(init_ovbd_target);
module_exit(cleanup_ovbd_target);

MODULE_AUTHOR("Rui Du <durui@linux.alibaba.com>");
MODULE_DESCRIPTION("DADI OverlayBD implementation as device mapper target");
MODULE_LICENSE("GPL");
