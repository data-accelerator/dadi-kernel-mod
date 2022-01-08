#include "zfile.h"

#include <linux/buffer_head.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/lz4.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/spinlock.h>
#include <linux/bio.h>
#include "vfsfile.h"
#include "log-format.h"

static const uint32_t ZF_SPACE = 512;
static uint64_t *MAGIC0 = (uint64_t *)"ZFile\0\1";
static const uuid_t MAGIC1 = UUID_INIT(0x74756a69, 0x2e79, 0x7966, 0x40, 0x41,
				       0x6c, 0x69, 0x62, 0x61, 0x62, 0x61);

static const uint32_t FLAG_SHIFT_HEADER = 0; // 1:header     0:trailer
static const uint32_t FLAG_SHIFT_TYPE = 1; // 1:data file, 0:index file
static const uint32_t FLAG_SHIFT_SEALED =
	2; // 1:YES,       0:NO  				# skip it now.
static const uint32_t FLAG_SHIFT_HEADER_OVERWRITE = 3;

uint32_t get_flag_bit(struct zfile_ht *ht, uint32_t shift)
{
	return ht->flags & (1 << shift);
}

bool is_header(struct zfile_ht *ht)
{
	return get_flag_bit(ht, FLAG_SHIFT_HEADER);
}

bool is_header_overwrite(struct zfile_ht *ht)
{
	return get_flag_bit(ht, FLAG_SHIFT_HEADER_OVERWRITE);
}

bool is_trailer(struct zfile_ht *ht)
{
	return !is_header(ht);
}

size_t zfile_len(struct vfile *zfile)
{
	return ((struct zfile *)zfile)->header.vsize;
}

ssize_t zfile_read(struct vfile *ctx, void *dst, size_t count, loff_t offset)
{
	struct zfile *zf = (struct zfile *)ctx;
	size_t start_idx, end_idx;
	loff_t begin, range;
	size_t bs;
	ssize_t ret;
	int dc;
	ssize_t i;
	char *src_buf;
	char *decomp_buf;
	loff_t decomp_offset;
	char *c_buf;
	loff_t poff;
	size_t pcnt;

	if (!zf) {
		PRINT_INFO("zfile: failed empty zf\n");
		return -EIO;
	}
	bs = zf->header.opt.block_size;
	// read empty
	if (count == 0)
		return 0;
	// read from over-tail
	if (offset > zf->header.vsize) {
		PRINT_INFO("zfile: read over tail %lld > %lld\n", offset,
			   zf->header.vsize);
		return 0;
	}
	// read till tail
	if (offset + count > zf->header.vsize) {
		count = zf->header.vsize - offset;
	}
	start_idx = offset / bs;
	end_idx = (offset + count - 1) / bs;

	begin = zf->jump[start_idx].partial_offset;
	range = zf->jump[end_idx].partial_offset + zf->jump[end_idx].delta -
		begin;

	src_buf = kmalloc(range, GFP_KERNEL);
	decomp_buf = kmalloc(zf->header.opt.block_size, GFP_KERNEL);
	PRINT_INFO("zfile: Read block from %lu to %lu\n", start_idx, end_idx);
	// read compressed data
	ret = zf->fp->op->pread(zf->fp, src_buf, range, begin);
	if (ret != range) {
		PRINT_ERROR("zfile: Read file failed, %ld != %lld", ret, range);
		ret = -EIO;
		goto fail_read;
	}

	c_buf = src_buf;

	// decompress in seq
	decomp_offset = offset - offset % bs;
	ret = 0;
	for (i = start_idx; i <= end_idx; i++) {
		dc = LZ4_decompress_safe(
			c_buf, decomp_buf,
			zf->jump[i].delta -
				(zf->header.opt.verify ? sizeof(uint32_t) : 0),
			bs);
		if (dc <= 0) {
			PRINT_ERROR("decompress failed");
			ret = -EIO;
			goto fail_read;
		}
		poff = offset - decomp_offset;
		pcnt = count > (dc - poff) ? (dc - poff) : count;
		memcpy(dst, decomp_buf + poff, pcnt);
		decomp_offset += dc;
		dst += pcnt;
		ret += pcnt;
		count -= pcnt;
		offset = decomp_offset;
		c_buf += zf->jump[i].delta;
	}

fail_read:
	kfree(decomp_buf);
	kfree(src_buf);

	return ret;
}

void build_jump_table(uint32_t *jt_saved, struct zfile *zf)
{
	size_t i;
	zf->jump = vmalloc((zf->header.index_size + 2) *
			   sizeof(struct jump_table));
	zf->jump[0].partial_offset = ZF_SPACE;
	for (i = 0; i < zf->header.index_size; i++) {
		zf->jump[i].delta = jt_saved[i];
		zf->jump[i + 1].partial_offset =
			zf->jump[i].partial_offset + jt_saved[i];
	}
}

void zfile_close(struct vfile *f)
{
	struct zfile *zfile = (struct zfile *)f;
	unsigned long index;
	struct page *entry;

	PRINT_INFO("close(%p)", (void *)f);
	if (zfile) {
		kthread_flush_worker(&zfile->worker);
		kthread_stop(zfile->worker_task);

		if (zfile->jump) {
			vfree(zfile->jump);
			zfile->jump = NULL;
		}
		zfile->fp = NULL;
		xa_for_each (&zfile->cpages, index, entry) {
			put_page(entry);
		}
		xa_destroy(&zfile->cpages);
		kfree(zfile);
	}
}

static int zf_decompress(struct zfile *zf, struct page *page, loff_t offset)
{
	void *dst = NULL;
	void *src, *holder;
	size_t idx, c_cnt;
	loff_t begin, end, pbegin, pend, i, k;
	struct xarray *pool = &zf->cpages;
	struct page *spage[3];
	bool single_page;
	int ret = 0;

	dst = kmap_atomic(page);
	idx = offset >> PAGE_SHIFT;
	begin = zf->jump[idx].partial_offset;
	end = zf->jump[idx].partial_offset + zf->jump[idx].delta;
	c_cnt = zf->jump[idx].delta -
		(zf->header.opt.verify ? sizeof(uint32_t) : 0);
	pbegin = begin >> PAGE_SHIFT;
	pend = (end + PAGE_SIZE - 1) >> PAGE_SHIFT;
	single_page = ((pend - pbegin) == 1);
	BUG_ON(pend - pbegin > 3);
	if (single_page) {
		// data in same page
		spage[0] = xa_load(pool, pbegin);
		if (!PageUptodate(spage[0])) {
			lock_page(spage[0]);
			unlock_page(spage[0]);
		}
		holder = kmap_atomic(spage[0]);
		src = holder + begin % PAGE_SIZE;
	} else {
		for (i = begin & PAGE_MASK; i < end; i += PAGE_SIZE) {
			k = (i >> PAGE_SHIFT) - pbegin;
			spage[k] = xa_load(pool, i >> PAGE_SHIFT);
			if (!PageUptodate(spage[k])) {
				lock_page(spage[k]);
				unlock_page(spage[k]);
			}
		}
		holder = vmap(&spage[0], pend - pbegin, VM_MAP, PAGE_KERNEL_RO);
		src = holder + begin % PAGE_SIZE;
	}

	ret = LZ4_decompress_safe(src, dst, c_cnt, PAGE_SIZE);

	if (single_page) {
		kunmap_atomic(holder);
	} else {
		vunmap(holder);
		for (i = 0; i < pend - pbegin; i++) {
			kunmap(holder);
			holder += 4096;
		}
	}
	kunmap_atomic(dst);

	if (ret < 0) {
		pr_err("Decompress error\n");
	}

	return ret;
}

static void cpages_endio(struct bio *bio)
{
	struct bvec_iter_all iter;
	struct bio_vec *bv;
	blk_status_t err = bio->bi_status;

	bio_for_each_segment_all (bv, bio, iter) {
		struct page *page = bv->bv_page;
		if (err)
			SetPageError(page);
		else
			SetPageUptodate(page);
		unlock_page(page);
	}
	bio_put(bio);
}

struct decompress_work {
	struct kthread_work work;
	struct zfile *zf;
	struct bio *bio;
};

static void do_decompress(struct zfile *zf, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	bio_for_each_segment (bv, bio, iter) {
		if (zf_decompress(zf, bv.bv_page,
				  (iter.bi_sector << SECTOR_SHIFT) &
					  PAGE_MASK) < 0) {
			pr_err("ZFile: error decompressing %llu\n",
			       (iter.bi_sector << SECTOR_SHIFT) & PAGE_MASK);
			bio_io_error(bio);
			break;
		}
	}
	bio_endio(bio);
}

static void decompress_fn(struct kthread_work *work)
{
	struct decompress_work *cmd =
		container_of(work, struct decompress_work, work);
	do_decompress(cmd->zf, cmd->bio);
	kfree(cmd);
}

static int zfile_bioremap(IFile *ctx, struct bio *bio, struct dm_dev **dm_dev,
			  unsigned int nr)
{
	struct zfile *zf = (struct zfile *)ctx;
	loff_t offset = bio->bi_iter.bi_sector;
	size_t count = bio_sectors(bio);
	size_t bs = zf->header.opt.block_size;
	size_t start_idx, end_idx;
	struct bio *subbio = NULL;
	struct page *page, *fetch;
	loff_t begin, range, i, right, left;
	struct xarray *cpages = &zf->cpages;
	int nr_pages;

	if (nr != 1 || !dm_dev[0]) {
		pr_err("ZFile: nr wrong\n");
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if ((bio_op(bio) != REQ_OP_READ)) {
		pr_err("ZFile: REQ not read\n");
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if ((offset << SECTOR_SHIFT) >= zf->header.vsize) {
		pr_err("ZFile: %lld over tail\n", offset);
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if (((offset + count) << SECTOR_SHIFT) > zf->header.vsize) {
		pr_err("ZFile: %lld over tail\n", offset);
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	start_idx = (offset << SECTOR_SHIFT) / bs;
	end_idx = ((offset + count - 1) << SECTOR_SHIFT) / bs;

	begin = zf->jump[start_idx].partial_offset;
	range = zf->jump[end_idx].partial_offset + zf->jump[end_idx].delta -
		begin;
	left = begin & PAGE_MASK;
	right = (begin + range + PAGE_SIZE - 1) & PAGE_MASK;
	nr_pages = (right - left) >> PAGE_SHIFT;

	// issuring read page cache
	// pre-alloc pages
	for (i = left; i < begin + range; i += PAGE_SIZE) {
		page = xa_load(cpages, i >> PAGE_SHIFT);
		if (!page) {
			page = alloc_page(GFP_KERNEL);
			lock_page(page);
			ClearPageUptodate(page);
			fetch = xa_cmpxchg(cpages, i >> PAGE_SHIFT, NULL, page,
					   GFP_KERNEL);
			if (fetch) {
				unlock_page(page);
				put_page(page);
				page = fetch;
			} else {
				subbio = bio_alloc(GFP_KERNEL, 1);
				bio_add_page(subbio, page, PAGE_SIZE, 0);
				bio_set_dev(subbio, dm_dev[0]->bdev);
				bio_set_op_attrs(subbio, REQ_OP_READ, 0);
				subbio->bi_end_io = cpages_endio;
				subbio->bi_private = zf;
				subbio->bi_iter.bi_sector = i >> SECTOR_SHIFT;
				submit_bio(subbio);
			}
		}
	}

	struct decompress_work *cmd =
		kmalloc(sizeof(struct decompress_work), GFP_KERNEL);
	cmd->bio = bio;
	cmd->zf = zf;
	kthread_init_work(&cmd->work, &decompress_fn);
	kthread_queue_work(&zf->worker, &cmd->work);
	return DM_MAPIO_SUBMITTED;
}

static struct vfile_op zfile_ops = { .len = zfile_len,
				     .pread = zfile_read,
				     .pread_async = NULL,
				     .bio_remap = zfile_bioremap,
				     .close = zfile_close };

static int zf_io_worker_fn(void *worker_ptr)
{
	current->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
	return kthread_worker_fn(worker_ptr);
}
IFile *zfile_open_by_file(struct vfile *file)
{
	uint32_t *jt_saved;
	size_t jt_size = 0;
	struct zfile *zfile = NULL;
	int ret = 0;
	size_t file_size = 0;
	loff_t tailer_offset;
	zfile = kzalloc(sizeof(struct zfile), GFP_KERNEL);

	if (!is_zfile(file, &zfile->header)) {
		kfree(zfile);
		return NULL;
	}

	xa_init(&zfile->cpages);
	if (!zfile) {
		goto error_out;
	}
	zfile->fp = file;

	// should verify header
	if (!is_header_overwrite(&zfile->header)) {
		file_size = zfile->fp->op->len(zfile->fp);
		tailer_offset = file_size - ZF_SPACE;
		PRINT_INFO("zfile: file_size=%lu tail_offset=%llu\n", file_size,
			   tailer_offset);
		ret = zfile->fp->op->pread(zfile->fp, &zfile->header,
					   sizeof(struct zfile_ht),
					   tailer_offset);
		PRINT_INFO(
			"zfile: Trailer vsize=%lld index_offset=%lld index_size=%lld "
			"verify=%d",
			zfile->header.vsize, zfile->header.index_offset,
			zfile->header.index_size, zfile->header.opt.verify);
	} else {
		PRINT_INFO(
			"zfile header overwrite: size=%lld index_offset=%lld "
			"index_size=%lld verify=%d",
			zfile->header.vsize, zfile->header.index_offset,
			zfile->header.index_size, zfile->header.opt.verify);
	}
	// PRINT_INFO("zfile: vlen=%lld size=%ld\n", zfile->header.vsize,
	// 	zfile_len((struct vfile *)zfile));

	jt_size = ((uint64_t)zfile->header.index_size) * sizeof(uint32_t);
	PRINT_INFO("get index_size %lu, index_offset %llu", jt_size,
		   zfile->header.index_offset);

	if (jt_size == 0 || jt_size > 1024UL * 1024 * 1024) {
		goto error_out;
	}

	jt_saved = vmalloc(jt_size);

	ret = zfile->fp->op->pread(zfile->fp, jt_saved, jt_size,
				   zfile->header.index_offset);

	build_jump_table(jt_saved, zfile);

	vfree(jt_saved);

	zfile->vfile.op = &zfile_ops;

	kthread_init_worker(&zfile->worker);
	zfile->worker_task =
		kthread_run(zf_io_worker_fn, &zfile->worker, "io thread init");
	if (IS_ERR(zfile->worker_task))
		goto error_out;
	set_user_nice(zfile->worker_task, MIN_NICE);

	return (IFile *)zfile;

error_out:
	if (zfile)
		zfile_close((struct vfile *)zfile);
	return NULL;
}

IFile *zfile_open(const char *path)
{
	IFile *ret = NULL;
	IFile *file = open_path_as_vfile(path, 0, 644);
	if (!file) {
		PRINT_ERROR("zfile: Canot open zfile %s", path);
		goto fail;
	}
	ret = zfile_open_by_file(file);
	if (!ret) {
		goto fail;
	}
	return (IFile *)ret;
fail:
	file->op->close(file);
	return NULL;
}

bool is_zfile(struct vfile *file, struct zfile_ht *ht)
{
	ssize_t ret;
	if (!file)
		return false;

	ret = file->op->pread(file, ht, sizeof(struct zfile_ht), 0);
	if (ret < (ssize_t)sizeof(struct zfile_ht)) {
		PRINT_INFO("zfile: failed to load header %ld", ret);
		return false;
	}
	return ht->magic0 == *MAGIC0 && uuid_equal(&(ht->magic1), &MAGIC1);
}
