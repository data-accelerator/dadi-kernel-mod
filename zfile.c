#include "dm-ovbd.h"
#include <linux/lz4.h>
#include <linux/vmalloc.h>
#include <linux/prefetch.h>
#include <linux/kthread.h>
#include <linux/uuid.h>
#include <linux/dm-bufio.h>

static const uint32_t ZF_SPACE = 512;
static uint64_t *MAGIC0 = (uint64_t *)"ZFile\0\1";
static const uuid_t MAGIC1 = UUID_INIT(0x74756a69, 0x2e79, 0x7966, 0x40, 0x41,
				       0x6c, 0x69, 0x62, 0x61, 0x62, 0x61);

struct compress_options {
	uint32_t block_size; // 4
	uint8_t type; // 5
	uint8_t level; // 6
	uint8_t use_dict; // 7
	uint32_t args; // 11
	uint32_t dict_size; // 15
	uint8_t verify; // 16
};

_Static_assert(20 == sizeof(struct compress_options), "CO size not fit");

struct zfile_ht {
	uint64_t magic0; // 8
	uuid_t magic1; // 4+2+2+2+6 = 4 + 12 = 20

	// till here offset = 28
	uint32_t size_ht; //= sizeof(HeaderTrailer); // 32
	uint64_t flags; //= 0;                        // 40

	// till here offset = 40
	uint64_t index_offset; // in bytes  48
	uint64_t index_size; // num of index  56

	uint64_t vsize; // 64
	uint64_t reserved_0; // 72

	struct compress_options opt; // suppose to be 24
};

_Static_assert(96 == sizeof(struct zfile_ht), "Header size not fit");

struct jump_table {
	uint64_t partial_offset : 48; // 48 bits logical offset + 16 bits partial minimum
	uint16_t delta : 16;
} __attribute__((packed));

// zfile can be treated as file with extends
struct zfile {
	vfile_operations *ops;
	vfile *fp;
	bool onwership;
	struct block_device *blkdev;
	struct zfile_ht header;
	struct jump_table *jump;
	mempool_t cmdpool;
	struct dm_bufio_client *c;
	ovbd_context *ovbd;
};

#define FLAG_SHIFT_HEADER 0
// 1:header     0:trailer
#define FLAG_SHIFT_TYPE 1
// 1:data file, 0:index file
#define FLAG_SHIFT_SEALED 2
// 1:YES,       0:NO  				# skip it now.
#define FLAG_SHIFT_HEADER_OVERWRITE 3

#define PREFETCH_PAGE_NR 32
#define BUFIO_RESERVED_PAGE_NR 128
#define CMDPOOL_SIZE 4096
#define MAX_JUMPTABLE_SIZE (1024UL * 1024 * 1024)

static size_t zfile_len(vfile *fp);
static void zfile_close(vfile *ctx);
static int zfile_bioremap(vfile *ctx, struct bio *bio, struct dm_dev **dev,
			  unsigned nr);

static vfile_operations zfile_ops = { .len = zfile_len,
				      .bio_remap = zfile_bioremap,
				      .close = zfile_close };

#ifdef ZFILE_HEAD_OVERWRITE
static uint32_t get_flag_bit(struct zfile_ht *ht, uint32_t shift)
{
	return ht->flags & (1 << shift);
}
#endif

static bool is_header_overwrite(struct zfile_ht *ht)
{
#ifdef ZFILE_HEAD_OVERWRITE
	return get_flag_bit(ht, FLAG_SHIFT_HEADER_OVERWRITE);
#else
	return false;
#endif
}

static size_t zfile_len(struct vfile *zfile)
{
	return ((struct zfile *)zfile)->header.vsize;
}

static void build_jump_table(uint32_t *jt_saved, struct zfile *zf)
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
	struct dm_buffer *buf;
	void *tmp = NULL;

	idx = offset >> PAGE_SHIFT;
	begin = zf->jump[idx].partial_offset;
	c_cnt = zf->jump[idx].delta -
		(zf->header.opt.verify ? sizeof(uint32_t) : 0);
	left = begin & PAGE_MASK;
	right = ((begin + c_cnt) + (PAGE_SIZE - 1)) & PAGE_MASK;

	if (likely(right - left == PAGE_SIZE && !force)) {
		src = dm_bufio_get(zf->c, left >> PAGE_SHIFT, &buf);
		if (IS_ERR_OR_NULL(src)) {
			return ZFILE_DECOMP_NOT_READY;
		}
		BUG_ON(IS_ERR(buf));
		BUG_ON(IS_ERR(src));
		src = src + (begin - left);
	} else {
		tmp = kmalloc(right - left, GFP_KERNEL);
		for (i = left; i < right; i += PAGE_SIZE) {
			void *d = dm_bufio_read(zf->c, i >> PAGE_SHIFT, &buf);
			if (IS_ERR_OR_NULL(d)) {
				kfree(tmp);
				return ZFILE_DECOMP_NOT_READY;
			}
			BUG_ON(IS_ERR(buf));
			BUG_ON(IS_ERR(d));
			memcpy(tmp + i - left, d, PAGE_SIZE);
			dm_bufio_release(buf);
		}
		src = tmp + (begin - left);
	}

	dst = kmap_atomic(page);

	prefetchw(dst);

	ret = LZ4_decompress_fast(src, dst, PAGE_SIZE);

	kunmap_atomic(dst);

	if (ret < 0) {
		pr_err("Decompress error\n");
	}

	if (tmp) {
		kfree(tmp);
	} else {
		dm_bufio_release(buf);
	}

	return ZFILE_DECOMP_OK;
}

static int do_decompress(struct zfile *zf, struct bio *bio, size_t left, int nr,
			 bool force)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	bio_for_each_segment (bv, bio, iter) {
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

inline static void zfile_prefetch(struct zfile *zf, size_t left, size_t nr)
{
#ifdef ZFILE_READAHEAD
	size_t prefetch_page = PREFETCH_PAGE_NR;
#else
	size_t prefetch_page = 0;
#endif
	dm_bufio_prefetch(zf->c, left >> PAGE_SHIFT, nr + prefetch_page);
}

inline static void zfile_cleanup_compressed_cache(struct zfile *zf, size_t left,
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
	BUG_ON(!work);
	BUG_ON(!cmd);
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
	BUG_ON(!queue_work(cmd->zf->ovbd->wq, work));
}

static int zfile_bioremap(vfile *ctx, struct bio *bio, struct dm_dev **dm_dev,
			  unsigned int nr)
{
	struct zfile *zf = (struct zfile *)ctx;
	loff_t offset = bio->bi_iter.bi_sector;
	size_t count = bio_sectors(bio);

	struct decompress_work *cmd;

	if (unlikely(nr != 1 || !dm_dev[0])) {
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
	BUG_ON(IS_ERR_OR_NULL(cmd));

	INIT_WORK(&cmd->work, decompress_fn);
	cmd->bio = bio;
	cmd->zf = zf;
	cmd->force = false;

	BUG_ON(!queue_work(cmd->zf->ovbd->wq, &cmd->work));
	return DM_MAPIO_SUBMITTED;
}

static bool load_zfile_header(vfile *file, struct zfile_ht *ht);

vfile *zfile_open(struct vfile *file)
{
	uint32_t *jt_saved;
	size_t jt_size = 0;
	struct zfile *zfile = NULL;
	int ret = 0;
	size_t file_size = 0;
	loff_t tailer_offset;
	struct block_device *bdev = file->ops->blkdev(file);
	zfile = kzalloc(sizeof(struct zfile), GFP_KERNEL);

	if (!load_zfile_header(file, &zfile->header)) {
		kfree(zfile);
		return NULL;
	}

	if (!zfile) {
		goto error_out;
	}
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
		pr_info("zfile: Trailer vsize=%lld index_offset=%lld index_size=%lld "
			"verify=%d",
			zfile->header.vsize, zfile->header.index_offset,
			zfile->header.index_size, zfile->header.opt.verify);
	} else {
		pr_info("zfile header overwrite: size=%lld index_offset=%lld "
			"index_size=%lld verify=%d",
			zfile->header.vsize, zfile->header.index_offset,
			zfile->header.index_size, zfile->header.opt.verify);
	}

	jt_size = ((uint64_t)zfile->header.index_size) * sizeof(uint32_t);
	pr_info("get index_size %lu, index_offset %llu", jt_size,
		zfile->header.index_offset);

	if (jt_size == 0 || jt_size > MAX_JUMPTABLE_SIZE) {
		goto error_out;
	}

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

	zfile->c = dm_bufio_client_create(
		bdev, PAGE_SIZE, BUFIO_RESERVED_PAGE_NR, 0, NULL, NULL);
	if (IS_ERR_OR_NULL(zfile->c))
		goto error_out;

	zfile->ovbd = get_ovbd_context();

	return (vfile *)zfile;

error_out:
	if (zfile) {
		zfile_close((struct vfile *)zfile);
	}
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
	return ht->magic0 == *MAGIC0 && uuid_equal(&(ht->magic1), &MAGIC1);
}

static void zfile_close(vfile *f)
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
		if (!IS_ERR_OR_NULL((zfile->c)))
			dm_bufio_client_destroy(zfile->c);
		kfree(zfile);
	}
}
