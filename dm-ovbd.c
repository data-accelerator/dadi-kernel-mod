#include "dm-lsmt.h"
#include "dm-zfile.h"
#include <linux/module.h>

static int init_ovbd_target(void)
{
	if (init_lsmt_target() < 0)
		return -1;
	if (init_zfile_target() < 0)
		return -1;
	return 0;
}

static void cleanup_ovbd_target(void)
{
	cleanup_zfile_target();
	cleanup_lsmt_target();
}

module_init(init_ovbd_target);
module_exit(cleanup_ovbd_target);
MODULE_LICENSE("GPL");