// SPDX-License-Identifier: GPL-2.0

#include "dm-ovbd.h"
#include <linux/lz4.h>
#include <linux/vmalloc.h>
#include <linux/prefetch.h>
#include <linux/kthread.h>
#include <linux/uuid.h>
#include <linux/dm-bufio.h>
#include <linux/build_bug.h>

static const u32 ZF_SPACE = 512;
static u64 *MAGIC0 = (u64 *)"ZFile\0\1";
static const uuid_t MAGIC1 = UUID_INIT(0x74756a69, 0x2e79, 0x7966, 0x40, 0x41,
				       0x6c, 0x69, 0x62, 0x61, 0x62, 0x61);

struct compress_options {
	u32 block_size; // 4
	u8 type; // 5
	u8 level; // 6
	u8 use_dict; // 7
	u8 __padding0; // 8
	u32 args; // 12
	u32 dict_size; // 16
	u8 verify; // 17
	u8 __padding1[7]; //24
} __packed;

static_assert(sizeof(struct compress_options) == 24, "CO size not fit");

struct zfile_ht {
	u64 magic0; // 8
	uuid_t magic1; // 24

	// till here offset = 24
	u32 size_ht; //= sizeof(HeaderTrailer); // 28
	u8 __padding[4]; // 32
	u64 flags; //= 0;                        // 40

	// till here offset = 36
	u64 index_offset; // in bytes  48
	u64 index_size; // num of index  56

	u64 vsize; // 64
	u64 reserved_0; // 72

	struct compress_options opt; // suppose to be 96
} __packed;

static_assert(sizeof(struct zfile_ht) == 96, "Header size not fit");

struct jump_table {
	u64 partial_offset : 48; // 48 bits logical offset + 16 bits partial minimum
	uint16_t delta : 16;
} __packed;

// zfile can be treated as file with extends
struct zfile {
	struct vfile_operations *ops;
	struct vfile *fp;
	bool ownership;
	struct block_device *blkdev;
	struct zfile_ht header;
	struct jump_table *jump;
	mempool_t cmdpool;
	struct dm_bufio_client *c;
	struct ovbd_context *ovbd;
};

#define FLAG_SHIFT_HEADER 0
// 1:header     0:trailer
#define FLAG_SHIFT_TYPE 1
// 1:data file, 0:index file
#define FLAG_SHIFT_SEALED 2
// 1:YES	0:NO				# skip it now.
#define FLAG_SHIFT_HEADER_OVERWRITE 3

#define PREFETCH_PAGE_NR 32
#define CMDPOOL_SIZE 4096
#define MAX_JUMPTABLE_SIZE (1024UL * 1024 * 1024)

static size_t zfile_len(struct vfile *fp);
static void zfile_close(struct vfile *ctx);
static int zfile_bioremap(struct vfile *ctx, struct bio *bio, struct dm_dev **dev,
			  unsigned int nr);

static struct vfile_operations zfile_ops = { .len = zfile_len,
					     .bio_remap = zfile_bioremap,
					     .close = zfile_close };

static u32 get_flag_bit(struct zfile_ht *ht, u32 shift)
{
	return ht->flags & (1 << shift);
}

static bool is_header_overwrite(struct zfile_ht *ht)
{
	return get_flag_bit(ht, FLAG_SHIFT_HEADER_OVERWRITE);
}

static size_t zfile_len(struct vfile *zfile)
{
	return ((struct zfile *)zfile)->header.vsize;
}

static void build_jump_table(u32 *jt_saved, struct zfile *zf)
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

enum decompress_result {
	ZFILE_DECOMP_ERROR = -1,
	ZFILE_DECOMP_OK = 0,
	ZFILE_DECOMP_NOT_READY = 1,
};

static int zf_decompress(struct zfile *zf, struct page *page, loff_t offset,
			 bool force)
{
	void *dst = NULL;
	void *src = NULL;
	size_t idx, c_cnt;
	loff_t begin, left, right, i;
	int ret = 0;
	int decomp_cnt = 0;
	struct dm_buffer *buf = NULL;
	void *tmp = NULL;

	idx = offset >> PAGE_SHIFT;
	begin = zf->jump[idx].partial_offset;
	c_cnt = zf->jump[idx].delta - (zf->header.opt.verify ? sizeof(u32) : 0);
	left = begin & PAGE_MASK;
	right = ((begin + c_cnt) + (PAGE_SIZE - 1)) & PAGE_MASK;

	if (likely(right - left == PAGE_SIZE)) {
		if (force)
			src = dm_bufio_read(zf->c, left >> PAGE_SHIFT, &buf);
		else
			src = dm_bufio_get(zf->c, left >> PAGE_SHIFT, &buf);
		if (IS_ERR_OR_NULL(src) || IS_ERR_OR_NULL(buf)) {
			ret = ZFILE_DECOMP_NOT_READY;
			goto out;
		}
		src = src + (begin - left);
	} else {
		tmp = kmalloc(right - left, GFP_KERNEL);
		for (i = left; i < right; i += PAGE_SIZE) {
			void *d = force ? dm_bufio_read(zf->c, i >> PAGE_SHIFT,
							&buf) :
					  dm_bufio_get(zf->c, i >> PAGE_SHIFT,
						       &buf);
			if (IS_ERR_OR_NULL(d) || IS_ERR_OR_NULL(buf)) {
				ret = ZFILE_DECOMP_NOT_READY;
				goto out;
			}
			memcpy(tmp + i - left, d, PAGE_SIZE);
			dm_bufio_release(buf);
			buf = NULL;
		}
		src = tmp + (begin - left);
	}

	dst = kmap_local_page(page);

	prefetchw(dst);

	decomp_cnt = LZ4_decompress_fast(src, dst, PAGE_SIZE);

	kunmap_local(dst);

	if (decomp_cnt < 0) {
		pr_err("Decompress error\n");
		ret = ZFILE_DECOMP_ERROR;
		goto out;
	}

out:
	if (!IS_ERR_OR_NULL(buf))
		dm_bufio_release(buf);
	kfree(tmp);

	return ret;
}

static int do_decompress(struct zfile *zf, struct bio *bio, size_t left, int nr,
			 bool force)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	bio_for_each_segment(bv, bio, iter) {
		int ret =
			zf_decompress(zf, bv.bv_page,
				      (iter.bi_sector << SECTOR_SHIFT), force);
		if (unlikely(ret != ZFILE_DECOMP_OK)) {
			if (ret == ZFILE_DECOMP_ERROR)
				bio_io_error(bio);
			return ret;
		}
	}
	bio_endio(bio);
	return ZFILE_DECOMP_OK;
}

struct decompress_work {
	struct work_struct work;
	struct zfile *zf;
	struct bio *bio;
	bool force;
};

static inline void zfile_prefetch(struct zfile *zf, size_t left, size_t nr)
{
#ifdef ZFILE_READAHEAD
	size_t prefetch_page = PREFETCH_PAGE_NR;
#else
	size_t prefetch_page = 0;
#endif
	dm_bufio_prefetch(zf->c, left >> PAGE_SHIFT, nr + prefetch_page);
}

static inline void zfile_cleanup_compressed_cache(struct zfile *zf, size_t left,
						  size_t nr)
{
#ifdef ZFILE_CLEANUP_CACHE
	dm_bufio_forget_buffers(zf->c, left >> PAGE_SHIFT, nr);
#endif
}

static void decompress_fn(struct work_struct *work)
{
	size_t start_idx, end_idx, begin, range, left, right;
	loff_t offset, count, nr;
	size_t bs;
	struct decompress_work *cmd =
		container_of(work, struct decompress_work, work);

	if (!work)
		return;
	offset = cmd->bio->bi_iter.bi_sector;
	count = bio_sectors(cmd->bio);
	bs = cmd->zf->header.opt.block_size;

	start_idx = (offset << SECTOR_SHIFT) / bs;
	end_idx = ((offset + count - 1) << SECTOR_SHIFT) / bs;

	begin = cmd->zf->jump[start_idx].partial_offset;
	range = cmd->zf->jump[end_idx].partial_offset +
		cmd->zf->jump[end_idx].delta - begin;
	left = begin & PAGE_MASK;
	right = (begin + range + PAGE_SIZE - 1) & PAGE_MASK;
	nr = (right - left) >> PAGE_SHIFT;

	zfile_prefetch(cmd->zf, left, nr);

	if (unlikely(do_decompress(cmd->zf, cmd->bio, left, nr, cmd->force) ==
		     ZFILE_DECOMP_NOT_READY)) {
		goto resubmit;
	}

	zfile_cleanup_compressed_cache(cmd->zf, left,
				       nr - ((right > begin + range) ? 1 : 0));

	mempool_free(cmd, &cmd->zf->cmdpool);

	return;

resubmit:
	cmd->force = true;
	queue_work(cmd->zf->ovbd->wq, work);
}

static int zfile_bioremap(struct vfile *ctx, struct bio *bio, struct dm_dev **dm_dev,
			  unsigned int dev_nr)
{
	struct zfile *zf = (struct zfile *)ctx;
	loff_t offset = bio->bi_iter.bi_sector;
	size_t count = bio_sectors(bio);
	struct decompress_work *cmd;

	if (unlikely(dev_nr != 1 || !dm_dev[0])) {
		pr_err("ZFile: nr wrong\n");
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if (unlikely(bio_op(bio) != REQ_OP_READ)) {
		pr_err("ZFile: REQ not read\n");
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if (unlikely((offset << SECTOR_SHIFT) >= zf->header.vsize)) {
		pr_err("ZFile: %lld over tail\n", offset);
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if (unlikely(((offset + count) << SECTOR_SHIFT) > zf->header.vsize)) {
		pr_err("ZFile: %lld over tail\n", offset);
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}

	cmd = mempool_alloc(&zf->cmdpool, GFP_NOIO);
	if (IS_ERR_OR_NULL(cmd))
		return DM_MAPIO_DELAY_REQUEUE;

	INIT_WORK(&cmd->work, decompress_fn);
	cmd->bio = bio;
	cmd->zf = zf;
	cmd->force = false;

	queue_work_on(raw_smp_processor_id(), cmd->zf->ovbd->wq, &cmd->work);
	return DM_MAPIO_SUBMITTED;
}

static bool load_zfile_header(struct vfile *file, struct zfile_ht *ht);

struct vfile *zfile_open(struct vfile *file)
{
	u32 *jt_saved;
	size_t jt_size = 0;
	struct zfile *zfile = NULL;
	int ret = 0;
	size_t file_size = 0;
	loff_t tailer_offset;
	struct block_device *bdev = file->ops->blkdev(file);

	zfile = kzalloc(sizeof(*zfile), GFP_KERNEL);

	if (!load_zfile_header(file, &zfile->header)) {
		kfree(zfile);
		return NULL;
	}

	if (!zfile)
		goto error_out;
	zfile->fp = file;

	// should verify header
	if (!is_header_overwrite(&zfile->header)) {
		file_size = zfile->fp->ops->len(zfile->fp);
		tailer_offset = file_size - ZF_SPACE;
		pr_info("zfile: file_size=%lu tail_offset=%llu\n", file_size,
			tailer_offset);
		ret = zfile->fp->ops->pread(zfile->fp, &zfile->header,
					    sizeof(struct zfile_ht),
					    tailer_offset);
		if (ret < (ssize_t)sizeof(struct zfile_ht)) {
			pr_err("zfile: failed to fetch zfile tailer");
			goto error_out;
		}
		pr_info("zfile: Trailer vsize=%lld index_offset=%lld index_size=%lld verify=%d",
			zfile->header.vsize, zfile->header.index_offset,
			zfile->header.index_size, zfile->header.opt.verify);
	} else {
		pr_info("zfile header overwrite: size=%lld index_offset=%lld index_size=%lld verify=%d",
			zfile->header.vsize, zfile->header.index_offset,
			zfile->header.index_size, zfile->header.opt.verify);
	}

	jt_size = ((u64)zfile->header.index_size) * sizeof(u32);
	pr_info("get index_size %lu, index_offset %llu", jt_size,
		zfile->header.index_offset);

	if (jt_size == 0 || jt_size > MAX_JUMPTABLE_SIZE)
		goto error_out;

	jt_saved = vmalloc(jt_size);

	ret = zfile->fp->ops->pread(zfile->fp, jt_saved, jt_size,
				    zfile->header.index_offset);

	build_jump_table(jt_saved, zfile);

	vfree(jt_saved);

	zfile->ops = &zfile_ops;

	ret = mempool_init_kmalloc_pool(&zfile->cmdpool, CMDPOOL_SIZE,
					sizeof(struct decompress_work));
	if (ret)
		goto error_out;

	zfile->c = dm_bufio_client_create(bdev, PAGE_SIZE, 1, 0, NULL, NULL);
	if (IS_ERR_OR_NULL(zfile->c))
		goto error_out;

	zfile->ovbd = get_ovbd_context();

	return (struct vfile *)zfile;

error_out:
	if (zfile)
		zfile_close((struct vfile *)zfile);
	return NULL;
}

static bool load_zfile_header(struct vfile *file, struct zfile_ht *ht)
{
	ssize_t ret;

	if (!file)
		return false;

	ret = file->ops->pread(file, ht, sizeof(struct zfile_ht), 0);
	if (ret < (ssize_t)sizeof(struct zfile_ht)) {
		pr_info("zfile: failed to load header %ld", ret);
		return false;
	}
	return ht->magic0 == *MAGIC0 && uuid_equal(&ht->magic1, &MAGIC1);
}

static void zfile_close(struct vfile *f)
{
	struct zfile *zfile = (struct zfile *)f;

	pr_info("close(%p)", (void *)f);
	if (zfile) {
		if (zfile->jump) {
			vfree(zfile->jump);
			zfile->jump = NULL;
		}
		zfile->fp = NULL;
		mempool_exit(&zfile->cmdpool);
		if (!IS_ERR_OR_NULL(zfile->c))
			dm_bufio_client_destroy(zfile->c);
		kfree(zfile);
	}
}
