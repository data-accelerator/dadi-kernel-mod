#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "zfile.h"
#include "blkfile.h"

/* This is a structure stores information about the underlying device
 * Param:
 *  dev : Underlying device
 *  start: Starting sector number of the device
 */
struct zfile_dm_target {
	struct dm_dev *dev;
	IFile *zfile;
	IFile *bf;
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

static int zfile_target_map(struct dm_target *ti, struct bio *bio)
{
	struct zfile_dm_target *mdt = (struct zfile_dm_target *)ti->private;
	// printk(KERN_CRIT "\n<<in function zfile_target_map \n");

	switch (bio_op(bio)) {
	case REQ_OP_READ:
		// pr_info("zfile: sec: %lld vcnt: %d\n", bio->bi_iter.bi_sector,
		//         bio->bi_vcnt);
		return mdt->zfile->op->bio_remap((struct vfile *)mdt->zfile,
						 bio, &mdt->dev, 1);
	}
	pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
	       bio_op(bio), bio->bi_status);
	return DM_MAPIO_KILL;
}

static int zfile_target_end_io(struct dm_target *ti, struct bio *bio,
			       blk_status_t *error)
{
	// struct zfile_dm_target *mdt = (struct zfile_dm_target *)ti->private;
	if (bio->bi_status != BLK_STS_OK) {
		pr_err("DONE NOT OK %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_ENDIO_REQUEUE;
	}
	return DM_ENDIO_DONE;
}

/* This is Constructor Function of basic target
 *  Constructor gets called when we create some device of type 'zfile_target'.
 *  So it will get called when we execute command 'dmsetup create'
 *  This  function gets called for each device over which you want to create
 * basic target. Here it is just a basic target so it will take only one device
 * so it will get called once.
 */
static int zfile_target_ctr(struct dm_target *ti, unsigned int argc,
			    char **argv)
{
	struct zfile_dm_target *mdt;
	const char *devname, *tail;
	struct dm_arg_set args = { .argc = argc, .argv = argv };
	size_t zflen;
	int ret;

	printk(KERN_CRIT "\n >>in function zfile_target_ctr \n");

	if (argc < 2) {
		printk(KERN_CRIT "\n Invalid no.of arguments.\n");
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	mdt = kzalloc(sizeof(struct zfile_dm_target), GFP_KERNEL);

	if (mdt == NULL) {
		printk(KERN_CRIT "\n Mdt is null\n");
		ti->error = "dm-zfile_target: Cannot allocate context";
		return -ENOMEM;
	}

	/* dm_get_table_mode
     * Gives out you the Permissions of device mapper table.
     * This table is nothing but the table which gets created
     * when we execute dmsetup create. This is one of the
     * Data structure used by device mapper for keeping track of its devices.
     *
     * dm_get_device
     * The function sets the mdt->dev field to underlying device dev structure.
     */

	devname = dm_shift_arg(&args);
	printk(KERN_INFO "\nzfile-md: load dev %s\n", devname);
	if (dm_get_device(ti, devname, dm_table_get_mode(ti->table),
			  &mdt->dev)) {
		ti->error = "dm-zfile_target: Device lookup failed";
		goto bad;
	}

	if (!mdt->dev || !mdt->dev->bdev) {
		pr_warn("failed to get mdt dev or bdev\n");
		goto error_out;
	}

	tail = dm_shift_arg(&args);
	ret = kstrtoul(tail, 10, &zflen);
	if (ret < 0) {
		pr_warn("failed to get file length");
		goto error_out;
	}

	mdt->bf = (struct vfile *)open_blkdev_as_vfile(mdt->dev->bdev, zflen);

	mdt->zfile = zfile_open_by_file((struct vfile *)mdt->bf);

	if (!mdt->zfile) {
		pr_crit("Failed to open zfile file");
		goto error_out;
	}

	pr_info("zfile: size is %lu\n",
		mdt->zfile->op->len((struct vfile *)mdt->zfile));

	ti->private = mdt;

	printk(KERN_CRIT "\n>>out function zfile_target_ctr \n");
	return 0;

error_out:
	if (mdt->zfile)
		mdt->zfile->op->close(mdt->zfile);
	if (mdt->bf)
		mdt->bf->op->close(mdt->bf);
	if (mdt->dev)
		dm_put_device(ti, mdt->dev);
bad:
	kfree(mdt);
	printk(KERN_CRIT "\n>>out function zfile_target_ctr with error \n");
	return -EINVAL;
}

/*
 * This is destruction function
 * This gets called when we remove a device of type basic target. The function
 * gets called per device.
 */
static void zfile_target_dtr(struct dm_target *ti)
{
	struct zfile_dm_target *mdt = (struct zfile_dm_target *)ti->private;
	printk(KERN_CRIT "\n<<in function zfile_target_dtr \n");
	if (mdt->zfile)
		mdt->zfile->op->close((struct vfile *)mdt->zfile);
	if (mdt->bf)
		mdt->bf->op->close((struct vfile *)mdt->bf);
	dm_put_device(ti, mdt->dev);
	kfree(mdt);
	printk(KERN_CRIT "\n>>out function zfile_target_dtr \n");
}

/*
 * This structure is fops for basic target.
 */
static struct target_type zfile_target = {
	.features = 0,
	.name = "zfile_target",
	.version = { 1, 0, 0 },
	.module = THIS_MODULE,
	.ctr = zfile_target_ctr,
	.dtr = zfile_target_dtr,
	.map = zfile_target_map,
	.end_io = zfile_target_end_io,
};

/*-------------------------------------------Module Functions
 * ---------------------------------*/

int init_zfile_target(void)
{
	int result;
	result = dm_register_target(&zfile_target);
	if (result < 0)
		printk(KERN_CRIT "\n Error in registering target \n");
	return 0;
}

void cleanup_zfile_target(void)
{
	dm_unregister_target(&zfile_target);
}
