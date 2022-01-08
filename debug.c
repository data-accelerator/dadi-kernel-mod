#include "blkfile.h"
#include "zfile.h"
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/printk.h>
#include <linux/blk_types.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

static struct block_device *bdev = NULL;

#define dev_to_bdev(device) container_of((device), struct block_device, bd_dev)

static int init_ovbd_target(void)
{
	size_t bsize;
	IFile *file, *zfile;
	struct page *page;
	char *mem;
	bdev = blkdev_get_by_path("/dev/vdb2", FMODE_READ, NULL);
	if (IS_ERR(bdev)) {
		bdev = NULL;
		return -EIO;
	}
	file = open_blkdev_as_vfile(bdev);
	if (!file)
		goto fail;
	printk("openfile\n");
	page = alloc_page(GFP_KERNEL);
	printk("alloc page\n");
	mem = vmalloc(65536);
	printk("len %p\n", file->op->len);
	bsize = file->op->len(file);
	printk("blk size = %ld\n", bsize);
	file->op->pread(file, mem, 512, 658971539 - 512);
	printk("result = %s\n", mem);

	zfile = zfile_open_by_file(file, 658971539);
	printk("file open done\n");
	zfile->op->pread(zfile, mem, 4096, 0);

	printk("data = %s\n", mem);

	zfile->op->close(zfile);
	file->op->close(file);
	vfree(mem);
	return 0;
fail:
	blkdev_put(bdev, FMODE_READ);
    bdev = NULL;
    return -1;
}

static void cleanup_ovbd_target(void)
{
	if (bdev)
		blkdev_put(bdev, FMODE_READ);
}

module_init(init_ovbd_target);
module_exit(cleanup_ovbd_target);
MODULE_LICENSE("GPL");