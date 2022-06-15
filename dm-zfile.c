#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "zfile.h"
#include "blkfile.h"

struct zfile_dm_target {
	struct dm_dev *dev;
	IFile *zfile;
	IFile *bf;
};

static int zfile_target_map(struct dm_target *ti, struct bio *bio)
{
	struct zfile_dm_target *mdt = (struct zfile_dm_target *)ti->private;

	switch (bio_op(bio)) {
	case REQ_OP_READ:
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
	if (bio->bi_status != BLK_STS_OK) {
		pr_err("DONE NOT OK %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_ENDIO_REQUEUE;
	}
	return DM_ENDIO_DONE;
}

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

	mdt->zfile = zfile_open_by_file(mdt->bf, mdt->dev->bdev);

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
