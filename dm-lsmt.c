#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "lsmt.h"
#include "blkfile.h"

/* This is a structure stores information about the underlying device
 * Param:
 *  dev : Underlying device
 *  start: Starting sector number of the device
 */
struct lsmt_dm_target {
	struct dm_dev *dev[256];
	IFile *lsmt;
	IFile *bf[256];
	unsigned int nr;
};

/* This is map function of basic target. This function gets called whenever you
 * get a new bio request.The working of map function is to map a particular bio
 * request to the underlying device. The request that we receive is submitted to
 * out device so  bio->bi_bdev points to our device. We should point to the
 * bio-> bi_dev field to bdev of underlying device. Here in this function, we
 * can have other processing like changing sector number of bio request,
 * splitting bio etc.
 *
 * Param :
 *  ti : It is the dm_target structure representing our basic target
 *  bio : The block I/O request from upper layer
 *  map_context : Its mapping context of target.
 *
 * Return values from target map function:
 *  DM_MAPIO_SUBMITTED :  Your target has submitted the bio request to
 * underlying request. DM_MAPIO_REMAPPED  :  Bio request is remapped, Device
 * mapper should submit bio. DM_MAPIO_REQUEUE   :  Some problem has happened
 * with the mapping of bio, So requeue the bio request. So the bio will be
 * submitted to the map function.
 */

static int lsmt_target_map(struct dm_target *ti, struct bio *bio)
{
	struct lsmt_dm_target *mdt = (struct lsmt_dm_target *)ti->private;

	if (!mdt) {
		pr_err("LSMT DM Target not ready!!\n");
		return DM_MAPIO_REQUEUE;
	}
	// printk(KERN_CRIT "\n<<in function lsmt_target_map \n");

	switch (bio_op(bio)) {
	case REQ_OP_READ:
		// pr_info("sec: %lld vcnt: %d\n", bio->bi_iter.bi_sector,
		// 	bio->bi_iter.bi_size);
		return mdt->lsmt->op->bio_remap((struct vfile *)mdt->lsmt, bio,
						mdt->dev, mdt->nr);
	}
	pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
	       bio_op(bio), bio->bi_status);
	return DM_MAPIO_KILL;
}

static int lsmt_target_end_io(struct dm_target *ti, struct bio *bio,
			      blk_status_t *error)
{
	//     struct lsmt_dm_target *mdt = (struct lsmt_dm_target *)ti->private;
	// pr_info("lsmt bio status = %d\n", bio->bi_status);
	if (bio->bi_status != BLK_STS_OK) {
		pr_err("DONE NOT OK %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_ENDIO_REQUEUE;
	}
	return DM_ENDIO_DONE;
}

/* This is Constructor Function of basic target
 *  Constructor gets called when we create some device of type 'lsmt_target'.
 *  So it will get called when we execute command 'dmsetup create'
 *  This  function gets called for each device over which you want to create
 * basic target. Here it is just a basic target so it will take only one device
 * so it will get called once.
 */
static int lsmt_target_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct lsmt_dm_target *mdt;
	const char *devname;
	const char *tail;
	struct dm_arg_set args = { .argc = argc, .argv = argv };
	size_t len;
	int ret;
	int i;

	printk(KERN_CRIT "\n >>in function lsmt_target_ctr \n");

	if (argc < 2) {
		printk(KERN_CRIT "\n Invalid no.of arguments.\n");
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	mdt = kmalloc(sizeof(struct lsmt_dm_target), GFP_KERNEL);

	if (mdt == NULL) {
		printk(KERN_CRIT "\n Mdt is null\n");
		ti->error = "dm-lsmt_target: Cannot allocate context";
		return -ENOMEM;
	}

	for (i = 0; *args.argv; i++) {
		devname = dm_shift_arg(&args);
		tail = dm_shift_arg(&args);
		ret = kstrtoul(tail, 10, &len);
		if (ret < 0) {
			pr_warn("Invalid parameter");
			goto error_out;
		}
		printk(KERN_INFO "\nlsmt-md: load dev %s\n", devname);
		if (dm_get_device(ti, devname, dm_table_get_mode(ti->table),
				  &mdt->dev[i])) {
			ti->error = "dm-lsmt_target: Device lookup failed";
			goto bad;
		}

		if (!mdt->dev[i] || !mdt->dev[i]->bdev) {
			pr_warn("failed to get mdt dev or bdev\n");
			goto error_out;
		}
		mdt->bf[i] = open_blkdev_as_vfile(mdt->dev[i]->bdev, len);
		pr_info("lsmt: file %d size %lu", i,
			mdt->bf[i]->op->len(mdt->bf[i]));
	}
	mdt->nr = i;

	// TODO: load multiple layer index
	mdt->lsmt = lsmt_open_files(mdt->bf, 1);

	if (!mdt->lsmt) {
		pr_crit("Failed to open lsmt file");
		goto error_out;
	}

	pr_info("dm-lsmt: blk size is %lu\n",
		mdt->lsmt->op->len((struct vfile *)mdt->lsmt));

	ti->private = mdt;

	printk(KERN_CRIT "\n>>out function lsmt_target_ctr \n");
	return 0;

error_out:
	for (i = 0; i < mdt->nr; i++) {
		if (mdt->bf[i])
			mdt->bf[i]->op->close((struct vfile *)mdt->bf[i]);
	}

	for (i = 0; i < mdt->nr; i++) {
		if (mdt->dev[i])
			dm_put_device(ti, mdt->dev[i]);
	}
bad:
	kfree(mdt);
	printk(KERN_CRIT "\n>>out function lsmt_target_ctr with error \n");
	return -EINVAL;
}

/*
 * This is destruction function
 * This gets called when we remove a device of type basic target. The function
 * gets called per device.
 */
static void lsmt_target_dtr(struct dm_target *ti)
{
	struct lsmt_dm_target *mdt = (struct lsmt_dm_target *)ti->private;
	unsigned int i = 0;
	printk(KERN_CRIT "\n<<in function lsmt_target_dtr \n");
	if (mdt->lsmt)
		mdt->lsmt->op->close((struct vfile *)mdt->lsmt);
	for (i = 0; i < mdt->nr; i++) {
		if (mdt->bf[i])
			mdt->bf[i]->op->close((struct vfile *)mdt->bf);
		dm_put_device(ti, mdt->dev[i]);
	}
	kfree(mdt);
	printk(KERN_CRIT "\n>>out function lsmt_target_dtr \n");
}

/*
 * This structure is fops for basic target.
 */
static struct target_type lsmt_target = {
	.features = 0,
	.name = "lsmt_target",
	.version = { 1, 0, 0 },
	.module = THIS_MODULE,
	.ctr = lsmt_target_ctr,
	.dtr = lsmt_target_dtr,
	.map = lsmt_target_map,
	.end_io = lsmt_target_end_io,
};

/*-------------------------------------------Module Functions
 * ---------------------------------*/

int init_lsmt_target(void)
{
	int result;
	result = dm_register_target(&lsmt_target);
	if (result < 0)
		printk(KERN_CRIT "\n Error in registering target \n");
	return 0;
}

void cleanup_lsmt_target(void)
{
	dm_unregister_target(&lsmt_target);
}
