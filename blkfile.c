#include "blkfile.h"
#include "log-format.h"
#include <linux/dm-bufio.h>

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
	if (right > (dsize << SECTOR_SHIFT)) {
		right = (dsize << SECTOR_SHIFT);
	}

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
	PRINT_INFO("blkdev_len %lld\n", bf->len);
	return bf->len;
}

static ssize_t blkdev_pread(struct vfile *ctx, void *buf, size_t count,
			    loff_t offset)
{
	struct blkdev_as_vfile *bf = (struct blkdev_as_vfile *)ctx;
	size_t ret, tr;
	ret = 0;
	while (count) {
		tr = sync_read_blkdev(
			bf, buf, count > 4 * PAGE_SIZE ? 4 * PAGE_SIZE : count,
			offset);
		if (tr < 0) {
			return tr;
		}
		if (tr == 0) {
			return ret;
		}
		ret += tr;
		buf += tr;
		offset += tr;
		count -= tr;
	}
	return ret;
}

static void blkdev_close(struct vfile *ctx)
{
	struct blkdev_as_vfile *bf = (struct blkdev_as_vfile *)ctx;
	if (ctx) {
		dm_bufio_client_destroy(bf->c);
		kfree(ctx);
	}
	return;
}

static struct vfile_op blkdev_op = {
	.len = blkdev_len,
	.pread = blkdev_pread,
	.pread_async = NULL,
	.bio_remap = NULL,
	.close = blkdev_close,
};

IFile *open_blkdev_as_vfile(struct block_device *blk, loff_t len)
{
	if (IS_ERR(blk)) {
		return NULL;
	}
	struct blkdev_as_vfile *ret =
		kzalloc(sizeof(struct blkdev_as_vfile), GFP_KERNEL);
	if (!ret)
		return NULL;
	ret->vfile.op = &blkdev_op;
	ret->c = dm_bufio_client_create(blk, 4096, 2, 0, NULL, NULL);
	if (IS_ERR(ret->c)) {
		goto errout;
	}
	// ret->dev = blk;
	if (len == -1)
		len = get_capacity(blk->bd_disk) << SECTOR_SHIFT;
	ret->len = len;
	// PRINT_INFO("open as vfile dev %p\n", ret->dev);
	return (IFile *)ret;
errout:
	kfree(ret);
	return NULL;
}
