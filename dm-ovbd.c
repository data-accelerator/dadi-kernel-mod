#include "dm-ovbd.h"

static ovbd_context global_ovbd_context;

int init_ovbd_target(void)
{
	int onlinecpus = num_possible_cpus();
	if (onlinecpus < 1) return -1;
	const unsigned int flags =
		WQ_UNBOUND | WQ_HIGHPRI;
	global_ovbd_context.wq = alloc_workqueue("ovbd", flags,
				    onlinecpus + onlinecpus / 4	);
	if (IS_ERR(global_ovbd_context.wq))
		return -1;
	if (init_lsmt_target() < 0)
		return -1;
	if (init_zfile_target() < 0)
		return -1;
	PRINT_INFO("OVBD initialized");
	return 0;
}

void cleanup_ovbd_target(void)
{
	cleanup_zfile_target();
	cleanup_lsmt_target();
	flush_workqueue(global_ovbd_context.wq);
	destroy_workqueue(global_ovbd_context.wq);
	global_ovbd_context.wq = NULL;
	PRINT_INFO("OVBD cleared");
}

ovbd_context* get_ovbd_context() {
	return &global_ovbd_context;
}

module_init(init_ovbd_target);
module_exit(cleanup_ovbd_target);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Du Rui <ray.dr@alibaba-inc.com>");
MODULE_DESCRIPTION("DADI OverlayBD implemention as device mapper target");