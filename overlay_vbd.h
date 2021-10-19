#ifndef __OVERLAY_VBD_H__
#define __OVERLAY_VBD_H__

#undef __KERNEL__
#ifndef HBDEBUG
#define HBDEBUG (1)
#endif

#include <linux/kthread.h>
#include <linux/blk-mq.h>

struct lsmt_file;
/*
 * Each block ovbd device has a radix_tree ovbd_pages of pages that stores
 * the pages containing the block device's contents. A ovbd page's ->index is
 * its offset in PAGE_SIZE units. This is similar to, but in no way connected
 * with, the kernel's pagecache or buffer cache (which sit above our block
 * device).
 */
struct ovbd_device {
	int ovbd_number;

	struct request_queue *ovbd_queue;
	struct gendisk *ovbd_disk;
	struct list_head ovbd_list;

	/*
	 * Backing store of pages and lock to protect it. This is the contents
	 * of the block device.
	 */
	// spinlock_t		ovbd_lock;
	// struct radix_tree_root	ovbd_pages;

	uint16_t block_size;

	// block-dev provides data by
	// using `lsmtfile_read`
	// assume block-dev size is `lsmtfile_len`
	struct vfile *fp;
	unsigned char *path;

	struct kthread_worker worker;
	struct task_struct *worker_task;

	struct blk_mq_tag_set tag_set;
	// bool initialized ;
};

struct ovbd_cmd {
	struct kthread_work work;
	long ret;
	struct bio_vec *bvec;
};

#endif
