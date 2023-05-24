// SPDX-License-Identifier: GPL-2.0

#include "dm-ovbd.h"
#include <linux/dm-bufio.h>

struct blkdev_as_vfile {
	struct vfile_operations *ops;
	struct block_device *blkdev;
	loff_t len;
	struct dm_bufio_client *c;
};

static struct block_device *blkdev_getblkdev(struct vfile *f)
{
	return ((struct blkdev_as_vfile *)f)->blkdev;
}

// special helper
// access blockdev data by sync
// copy to buffer
static ssize_t sync_read_blkdev(struct blkdev_as_vfile *f, void *buf,
				size_t count, loff_t offset)
{
	void *mem = NULL;
	loff_t left = offset & PAGE_MASK;
	loff_t right = (offset + count + PAGE_SIZE - 1) & PAGE_MASK;
	loff_t i = 0;
	size_t sg_len = 0;
	ssize_t ret = 0;
	int nr_pages = 0;
	size_t dsize = f->len;
	struct dm_buffer *dbuf = NULL;

	if (right > (dsize << SECTOR_SHIFT))
		right = (dsize << SECTOR_SHIFT);

	nr_pages = (right - left + PAGE_SIZE - 1) / PAGE_SIZE;
	dm_bufio_prefetch(f->c, left >> PAGE_SHIFT, nr_pages);

	for (i = 0; i < nr_pages; i++) {
		if (left > offset + count)
			break;
		sg_len = PAGE_SIZE;
		if (left + sg_len > offset + count)
			sg_len = offset + count - left;
		if (offset > left)
			sg_len = sg_len - (offset - left);
		mem = dm_bufio_read(f->c, left >> PAGE_SHIFT, &dbuf);
		if (IS_ERR(dbuf))
			goto out;
		memcpy(buf, mem + (offset - left), sg_len);
		dm_bufio_release(dbuf);
		buf += sg_len;
		offset += sg_len;
		left += PAGE_SIZE;
		ret += sg_len;
		count -= sg_len;
	}
out:
	return ret;
}

static size_t blkdev_len(struct vfile *ctx)
{
	struct blkdev_as_vfile *bf = (struct blkdev_as_vfile *)ctx;

	pr_debug("%s %lld\n", __func__, bf->len);
	return bf->len;
}

static ssize_t blkdev_pread(struct vfile *ctx, void *buf, size_t count,
			    loff_t offset)
{
	struct blkdev_as_vfile *bf;
	size_t ret, tr, split_count;

	bf = (struct blkdev_as_vfile *)ctx;
	ret = 0;
	while (count) {
		split_count = min((size_t)(PAGE_SIZE << 2), count);
		tr = sync_read_blkdev(bf, buf, split_count, offset);
		if (tr < 0)
			return tr;
		if (tr == 0)
			return ret;
		ret += tr;
		buf += tr;
		offset += tr;
		count -= tr;
	}
	return ret;
}

static void blkdev_close(struct vfile *ctx)
{
	struct blkdev_as_vfile *bf;

	bf = (struct blkdev_as_vfile *)ctx;
	if (ctx) {
		dm_bufio_client_destroy(bf->c);
		kfree(ctx);
	}
}

static struct vfile_operations blkdev_op = {
	.blkdev = blkdev_getblkdev,
	.len = blkdev_len,
	.pread = blkdev_pread,
	.bio_remap = NULL,
	.close = blkdev_close,
};

struct vfile *open_blkdev_as_vfile(struct block_device *blk, loff_t len)
{
	struct blkdev_as_vfile *ret;

	if (IS_ERR(blk))
		return NULL;
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return NULL;
	ret->ops = &blkdev_op;
	ret->blkdev = blk;
	ret->c = dm_bufio_client_create(blk, 4096, 1, 0, NULL, NULL);
	if (IS_ERR(ret->c))
		goto errout;
	if (len == -1)
		len = get_capacity(blk->bd_disk) << SECTOR_SHIFT;
	ret->len = len;
	return (struct vfile *)ret;
errout:
	kfree(ret);
	return NULL;
}
