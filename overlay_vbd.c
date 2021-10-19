// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "lsmt.h"
#include "zfile.h"
#include "overlay_vbd.h"

#define PAGE_SECTORS_SHIFT (PAGE_SHIFT - SECTOR_SHIFT)
#define OVBD_MAJOR 231
#define OVBD_CACHE_SIZE 536870912000

static const struct block_device_operations ovbd_fops = {
	.owner = THIS_MODULE,
};

/*
 * And now the modules code and kernel interface.
 */
static char *backfile = "/test.lsmtz";
module_param(backfile, charp, 0660);
MODULE_PARM_DESC(backfile, "Back file for lsmtz");

MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(OVBD_MAJOR);
MODULE_ALIAS("rd");

static void ovbd_unprepare_queue(struct ovbd_device *lo)
{
	kthread_flush_worker(&lo->worker);
	kthread_stop(lo->worker_task);
}

static int ovbd_kthread_worker_fn(void *worker_ptr)
{
	current->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
	return kthread_worker_fn(worker_ptr);
}

static int ovbd_prepare_queue(struct ovbd_device *lo, int idx)
{
	kthread_init_worker(&lo->worker);
	lo->worker_task =
		kthread_run(ovbd_kthread_worker_fn, &lo->worker, "loop%d", idx);
	if (IS_ERR(lo->worker_task))
		return -ENOMEM;
	set_user_nice(lo->worker_task, MIN_NICE);
	return 0;
}

/*
 * The device scheme is derived from loop.c. Keep them in synch where possible
 * (should share code eventually).
 */
static LIST_HEAD(ovbd_devices);
static DEFINE_MUTEX(ovbd_devices_mutex);

static int ovbd_read_simple(struct ovbd_device *ovbd, struct request *rq,
			    loff_t pos)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	ssize_t len;
	void *mem;

	rq_for_each_segment (bvec, rq, iter) {
		mem = kmap_atomic(bvec.bv_page);
		len = ovbd->fp->op->pread((struct vfile *)ovbd->fp,
					  mem + bvec.bv_offset, bvec.bv_len,
					  pos);
		kunmap_atomic(mem);

		if (len < bvec.bv_len) {
			return len;
		}

		if (len != bvec.bv_len) {
			struct bio *bio;

			__rq_for_each_bio (bio, rq)
				zero_fill_bio(bio);
			break;
		}
		flush_dcache_page(bvec.bv_page);
		cond_resched();
		pos += bvec.bv_len;
	}

	return 0;
}

static int do_req_filebacked(struct ovbd_device *lo, struct request *rq)
{
	loff_t pos;
	pos = ((loff_t)blk_rq_pos(rq) << 9);

	/*
     * lo_write_simple and lo_read_simple should have been covered
     * by io submit style function like lo_rw_aio(), one blocker
     * is that lo_read_simple() need to call flush_dcache_page after
     * the page is written from kernel, and it isn't easy to handle
     * this in io submit style function which submits all segments
     * of the req at one time. And direct read IO doesn't need to
     * run flush_dcache_page().
     */
	switch (req_op(rq)) {
	case REQ_OP_READ:
		return ovbd_read_simple(lo, rq, pos);
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}

static void ovbd_handle_cmd(struct ovbd_cmd *cmd)
{
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	const bool write = op_is_write(req_op(rq));
	struct ovbd_device *lo = rq->q->queuedata;
	int ret = 0;

	if (write) {
		ret = -EIO;
		goto failed;
	}

	ret = do_req_filebacked(lo, rq);
failed:
	/* complete non-aio request */
	if (ret) {
		if (ret == -EOPNOTSUPP) {
			cmd->ret = ret;
		} else {
			cmd->ret = ret ? -EIO : 0;
		}
	}
	blk_mq_complete_request(rq);
}

static void ovbd_queue_work(struct kthread_work *work)
{
	struct ovbd_cmd *cmd = container_of(work, struct ovbd_cmd, work);

	ovbd_handle_cmd(cmd);
}

static int ovbd_init_request(struct blk_mq_tag_set *set, struct request *rq,
			     unsigned int hctx_idx, unsigned int numa_node)
{
	struct ovbd_cmd *cmd = blk_mq_rq_to_pdu(rq);

	kthread_init_work(&cmd->work, ovbd_queue_work);
	return 0;
}

static blk_status_t ovbd_queue_rq(struct blk_mq_hw_ctx *hctx,
				  const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct ovbd_cmd *cmd = blk_mq_rq_to_pdu(rq);
	struct ovbd_device *lo = rq->q->queuedata;

	blk_mq_start_request(rq);

	/* always use the first bio's css */
	kthread_queue_work(&lo->worker, &cmd->work);

	return BLK_STS_OK;
}

static void ovbd_complete_rq(struct request *rq)
{
	struct ovbd_cmd *cmd = blk_mq_rq_to_pdu(rq);
	blk_status_t ret = BLK_STS_OK;

	if (cmd->ret < 0)
		ret = errno_to_blk_status(cmd->ret);
	blk_mq_end_request(rq, ret);
}

static const struct blk_mq_ops ovbd_mq_ops = {
	.queue_rq = ovbd_queue_rq,
	.init_request = ovbd_init_request,
	.complete = ovbd_complete_rq,
};

// 直接拿file对象来处理了
//比较偷懒的做法
static struct ovbd_device *ovbd_alloc(int i)
{
	struct ovbd_device *ovbd;
	struct gendisk *disk;
	int err;
	size_t flen;

	ovbd = kzalloc(sizeof(*ovbd), GFP_KERNEL);
	if (!ovbd)
		goto out;
	ovbd->ovbd_number = i;
	// spin_lock_init(&ovbd->ovbd_lock);
	// INIT_RADIX_TREE(&ovbd->ovbd_pages, GFP_ATOMIC);

	ovbd->tag_set.ops = &ovbd_mq_ops;
	ovbd->tag_set.nr_hw_queues = 1;
	ovbd->tag_set.queue_depth = 128;
	ovbd->tag_set.numa_node = NUMA_NO_NODE;
	ovbd->tag_set.cmd_size = sizeof(struct ovbd_cmd);
	ovbd->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_STACKING;
	ovbd->tag_set.driver_data = ovbd;

	err = blk_mq_alloc_tag_set(&ovbd->tag_set);
	if (err)
		goto out_free_dev;

	ovbd->ovbd_queue = blk_mq_init_queue(&ovbd->tag_set);
	if (IS_ERR(ovbd->ovbd_queue)) {
		err = PTR_ERR(ovbd->ovbd_queue);
		goto out_cleanup_tags;
	}
	ovbd->ovbd_queue->queuedata = ovbd;

	/* This is so fdisk will align partitions on 4k, because of
     * direct_access API needing 4k alignment, returning a PFN
     * (This is only a problem on very small devices <= 4M,
     *  otherwise fdisk will align on 1M. Regardless this call
     *  is harmless)
     */
	blk_queue_physical_block_size(ovbd->ovbd_queue, PAGE_SIZE);
	// blk_queue_logical_block_size(ovbd->ovbd_queue, PAGE_SIZE);
	// blk_queue_io_min(ovbd->ovbd_queue, PAGE_SIZE);

	disk = ovbd->ovbd_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;
	disk->major = OVBD_MAJOR;
	disk->first_minor = i;
	disk->fops = &ovbd_fops;
	disk->private_data = ovbd;
	disk->flags = GENHD_FL_EXT_DEVT | GENHD_FL_NO_PART_SCAN;
	sprintf(disk->disk_name, "vbd%d", i);
	pr_info("vbd: disk->disk_name %s\n", disk->disk_name);
	ovbd->fp = (struct vfile *)lsmt_open_ro(
		(struct vfile *)zfile_open(backfile), true);
	if (!ovbd->fp) {
		pr_info("Cannot load lsmtfile\n");
		goto out_free_queue;
	}
	err = ovbd_prepare_queue(ovbd, i);
	if (err)
		goto out_free_queue;

	// 此处为loop形式，文件长度即blockdev的大小
	// 如果是LSMTFile，则应以LSMTFile头记录的长度为准
	flen = ovbd->fp->op->len(ovbd->fp);
	ovbd->block_size = flen >> SECTOR_SHIFT;
	set_capacity(disk, flen >> SECTOR_SHIFT);
	ovbd->ovbd_queue->backing_dev_info->capabilities |=
		BDI_CAP_SYNCHRONOUS_IO;

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, ovbd->ovbd_queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, ovbd->ovbd_queue);
	set_disk_ro(disk, true);

	return ovbd;

out_free_queue:
	blk_cleanup_queue(ovbd->ovbd_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&ovbd->tag_set);
out_free_dev:
	kfree(ovbd);
out:
	return NULL;
}

static void ovbd_free(struct ovbd_device *ovbd)
{
	put_disk(ovbd->ovbd_disk);
	blk_cleanup_queue(ovbd->ovbd_queue);
	if (ovbd->fp)
		ovbd->fp->op->close(ovbd->fp);
	kfree(ovbd);
}

static struct ovbd_device *ovbd_init_one(int i, bool *new)
{
	struct ovbd_device *ovbd;

	*new = false;
	list_for_each_entry (ovbd, &ovbd_devices, ovbd_list) {
		if (ovbd->ovbd_number == i)
			goto out;
	}

	ovbd = ovbd_alloc(i);
	if (ovbd) {
		ovbd->ovbd_disk->queue = ovbd->ovbd_queue;
		pr_info("add_disk\n");
		add_disk(ovbd->ovbd_disk);
		list_add_tail(&ovbd->ovbd_list, &ovbd_devices);
	}
	*new = true;
out:
	return ovbd;
}

static void ovbd_del_one(struct ovbd_device *ovbd)
{
	list_del(&ovbd->ovbd_list);
	del_gendisk(ovbd->ovbd_disk);
	ovbd_unprepare_queue(ovbd);
	ovbd_free(ovbd);
}

static struct kobject *ovbd_probe(dev_t dev, int *part, void *data)
{
	struct ovbd_device *ovbd;
	struct kobject *kobj;
	bool new;

	mutex_lock(&ovbd_devices_mutex);
	printk("ovbd_probe");
	ovbd = ovbd_init_one(MINOR(dev), &new);
	kobj = ovbd ? get_disk_and_module(ovbd->ovbd_disk) : NULL;
	mutex_unlock(&ovbd_devices_mutex);

	if (new)
		*part = 0;

	return kobj;
}

static int __init ovbd_init(void)
{
	struct ovbd_device *ovbd, *next;
	int i;

	pr_info("vbd: INIT\n");

	if (register_blkdev(OVBD_MAJOR, "ovbd"))
		return -EIO;

	// 先打开文件再创建设备
	pr_info("alloc");
	for (i = 0; i < 1; i++) {
		ovbd = ovbd_alloc(i);
		if (!ovbd)
			goto out_free;
		list_add_tail(&ovbd->ovbd_list, &ovbd_devices);
	}

	/* point of no return */

	list_for_each_entry (ovbd, &ovbd_devices, ovbd_list) {
		/*
         * associate with queue just before adding disk for
         * avoiding to mess up failure path
         */
		pr_info("vbd: get filesize %d\n", ovbd->block_size);
		ovbd->ovbd_disk->queue = ovbd->ovbd_queue;
		pr_info("add_disk\n");
		add_disk(ovbd->ovbd_disk);
	}
	pr_info("Register blk\n");
	blk_register_region(MKDEV(OVBD_MAJOR, 0), 1UL << MINORBITS, THIS_MODULE,
			    ovbd_probe, NULL, NULL);

	pr_info("ovbd: module loaded\n");

	return 0;

out_free:
	list_for_each_entry_safe (ovbd, next, &ovbd_devices, ovbd_list) {
		list_del(&ovbd->ovbd_list);
		ovbd_free(ovbd);
	}
	unregister_blkdev(OVBD_MAJOR, "ovbd");
	pr_info("ovbd: module NOT loaded !!!\n");
	return -ENOMEM;
}

static void __exit ovbd_exit(void)
{
	struct ovbd_device *ovbd, *next;

	list_for_each_entry_safe (ovbd, next, &ovbd_devices, ovbd_list) {
		ovbd_del_one(ovbd);
	}

	blk_unregister_region(MKDEV(OVBD_MAJOR, 0), 1UL << MINORBITS);
	unregister_blkdev(OVBD_MAJOR, "ovbd");

	pr_info("ovbd: module unloaded\n");
}

module_init(ovbd_init);
module_exit(ovbd_exit);
