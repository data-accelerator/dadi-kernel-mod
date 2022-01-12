#include "blkfile.h"

// special helper
// access blockdev data by sync
// copy to buffer
static ssize_t sync_read_blkdev(struct block_device *dev, void *buf,
				size_t count, loff_t offset)
{
	void *mem = NULL;
	struct page *pg = NULL;
	struct bio *bio = NULL;
	loff_t left = offset & PAGE_MASK;
	loff_t right = (offset + count + PAGE_SIZE - 1) & PAGE_MASK;
	loff_t i = 0;
	size_t sg_len = 0;
	ssize_t ret = 0;
	int nr_pages = 0;
	size_t dsize = get_capacity(dev->bd_disk);
	struct page **pages = NULL;
	if (right > (dsize << SECTOR_SHIFT)) {
		right = (dsize << SECTOR_SHIFT);
	}

	nr_pages = (right - left + PAGE_SIZE - 1) / PAGE_SIZE;
	bio = bio_alloc(GFP_KERNEL, nr_pages);
	if (IS_ERR(bio)) {
		ret = -EIO;
		goto out;
	}
	bio_get(bio);

	pages = kmalloc(sizeof(struct page *) * nr_pages, GFP_KERNEL);

	for (i = left; i < right; i += PAGE_SIZE) {
		pg = alloc_page(GFP_NOIO);
		BUG_ON(!bio_add_page(
			bio, pg, right - i > PAGE_SIZE ? PAGE_SIZE : right - i,
			0));
		pages[(i - left) / PAGE_SIZE] = pg;
	}
	bio_set_dev(bio, dev);
	bio->bi_iter.bi_sector = left >> SECTOR_SHIFT;
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	submit_bio_wait(bio);

	if (bio->bi_status != BLK_STS_OK) {
		ret = -EIO;
		goto out;
	}

	for (i = 0; i < nr_pages; i++) {
		if (left > offset + count)
			break;
		sg_len = PAGE_SIZE;
		if (left + sg_len > offset + count)
			sg_len = offset + count - left;
		if (offset > left)
			sg_len = sg_len - (offset - left);
		mem = kmap_atomic(pages[i]);
		memcpy(buf, mem + (offset - left), sg_len);
		buf += sg_len;
		offset += sg_len;
		left += PAGE_SIZE;
		ret += sg_len;
		count -= sg_len;
		kunmap_atomic(mem);
	}
out:
	if (!IS_ERR(bio)) {
		bio_free_pages(bio);
		bio_put(bio);
	}
	return ret;
}

static size_t blkdev_len(struct vfile *ctx)
{
	struct blkdev_as_vfile *bf = (struct blkdev_as_vfile *)ctx;
	pr_info("blkdev_len %lld\n", bf->len);
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
			bf->dev, buf,
			count > 4 * PAGE_SIZE ? 4 * PAGE_SIZE : count, offset);
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
	if (!ctx)
		kfree(ctx);
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
	ret->dev = blk;
	if (len == -1)
		len = get_capacity(blk->bd_disk) << SECTOR_SHIFT;
	ret->len = len;
	// pr_info("open as vfile dev %p\n", ret->dev);
	return (IFile *)ret;
}
