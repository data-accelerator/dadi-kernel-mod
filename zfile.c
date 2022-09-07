#include "zfile.h"

#include <linux/version.h>
#include <linux/lz4.h>
#include <linux/vmalloc.h>
#include <linux/device-mapper.h>
#include <linux/prefetch.h>
#include "vfsfile.h"
#include "log-format.h"
#include "dm-ovbd.h"

static const uint32_t ZF_SPACE = 512;
static uint64_t *MAGIC0 = (uint64_t *)"ZFile\0\1";
static const uuid_t MAGIC1 = UUID_INIT(0x74756a69, 0x2e79, 0x7966, 0x40, 0x41,
				       0x6c, 0x69, 0x62, 0x61, 0x62, 0x61);

#define FLAG_SHIFT_HEADER 0
// 1:header     0:trailer
#define FLAG_SHIFT_TYPE 1
// 1:data file, 0:index file
#define FLAG_SHIFT_SEALED 2
// 1:YES,       0:NO  				# skip it now.
#define FLAG_SHIFT_HEADER_OVERWRITE 3

static size_t zfile_len(IFile *fp);
static void zfile_close(IFile *ctx);
static int zfile_bioremap(IFile *ctx, struct bio *bio, struct dm_dev **dev,
			  unsigned nr);

static struct vfile_op zfile_ops = { .len = zfile_len,
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

static int zf_decompress(struct zfile *zf, struct page *page, loff_t offset,
			 void *holder, loff_t holder_off)
{
	void *dst = NULL;
	void *src = NULL;
	size_t idx, c_cnt;
	loff_t begin;
	int ret = 0;

	idx = offset >> PAGE_SHIFT;
	begin = zf->jump[idx].partial_offset;
	c_cnt = zf->jump[idx].delta -
		(zf->header.opt.verify ? sizeof(uint32_t) : 0);

	src = holder + (begin - holder_off);

	dst = kmap_atomic(page);

	prefetchw(dst);

	ret = LZ4_decompress_safe(src, dst, c_cnt, PAGE_SIZE);

	kunmap_atomic(dst);

	if (ret < 0) {
		PRINT_ERROR("Decompress error %lld %lu %lld %lld %d\n", begin,
			    c_cnt, holder_off, begin - holder_off, ret);
	} else {
		ret = (((begin + zf->jump[idx].delta) & PAGE_MASK) == 0) ? 1 :
										 0;
	}

	return ret;
}

struct compressed_page_list {
	struct list_head list;
	struct page *page;
};

static inline void *zfile_vm_map_ram(struct page **pages, unsigned int count)
{
	int retried = 0;

	while (1) {
		void *p = vm_map_ram(pages, count, -1);

		/* retry two more times (totally 3 times) */
		if (p || ++retried >= 3)
			return p;
		vm_unmap_aliases();
	}
	return NULL;
}

static void do_decompress(struct zfile *zf, struct bio *bio, size_t left,
			  int nr, struct list_head *page_list, int gfp)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *holder;
	struct page **pages;
	struct compressed_page_list *cp;
	int i = 0, last;

	pages = kmalloc_array(nr, sizeof(struct page *), gfp);
	BUG_ON(!pages);

	list_for_each_entry (cp, page_list, list) {
		BUG_ON(!PageUptodate(cp->page));
		pages[i++] = cp->page;
	}

	holder = zfile_vm_map_ram(pages, nr);
	bio_for_each_segment (bv, bio, iter) {
		last = zf_decompress(zf, bv.bv_page,
				     (iter.bi_sector << SECTOR_SHIFT), holder,
				     left);
		if (unlikely(last < 0)) {
			bio_io_error(bio);
			return;
		}
	}
	bio_endio(bio);

	vm_unmap_ram(holder, nr);
	kfree(pages);

	invalidate_mapping_pages(zf->mapping, left >> PAGE_SHIFT, nr - last);
}

struct decompress_work {
	struct work_struct work;
	struct zfile *zf;
	struct bio *bio;
};

static inline struct page *
zfile_grab_cache_page_nowait(struct address_space *mapping, pgoff_t index)
{
	// return pagecache_get_page(mapping, index,
	// 			  FGP_LOCK | FGP_CREAT | FGP_NOFS | FGP_NOWAIT,
	// 			  readahead_gfp_mask(mapping) & ~__GFP_RECLAIM);
	return grab_cache_page_nowait(mapping, index);
}

static void zfile_read_endio(struct bio *bio)
{
	struct bio_vec *bvec;
	blk_status_t err = bio->bi_status;
	struct bvec_iter_all iter_all;

	bool no_put_page = bio_flagged(bio, BIO_NO_PAGE_REF);

	bio_for_each_segment_all (bvec, bio, iter_all) {
		struct page *page = bvec->bv_page;
		BUG_ON(PageUptodate(page));
		if (err)
			SetPageError(page);
		else
			SetPageUptodate(page);
		unlock_page(page);
		if (!no_put_page)
			put_page(page);

		/* page could be reclaimed now */
	}
	bio_put(bio);
}

static void decompress_slowpath(struct work_struct *work)
{
	size_t start_idx, end_idx, begin, range, left, right, i;
	loff_t offset, count, nr;
	size_t bs;
	struct decompress_work *cmd =
		container_of(work, struct decompress_work, work);
	struct compressed_page_list *cpl, *next;
	struct bio *bio;
	struct page *page;

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

	LIST_HEAD(list);

	for (i = left; i < right; i += PAGE_SIZE) {
		cpl = kmalloc(sizeof(struct compressed_page_list), GFP_KERNEL);
		list_add_tail(&cpl->list, &list);
		cpl->page = read_cache_page_gfp(cmd->zf->mapping,
						i >> SECTOR_SHIFT, GFP_KERNEL);
	}

	do_decompress(cmd->zf, cmd->bio, left, nr, &list, GFP_KERNEL);

	list_for_each_entry_safe (cpl, next, &list, list) {
		put_page(cpl->page);
		list_del(&cpl->list);
		kfree(cpl);
	}

	for (i = right;
	     i < min(right + 64ULL * PAGE_SIZE, cmd->zf->header.vsize);
	     i += PAGE_SIZE) {
		page = zfile_grab_cache_page_nowait(cmd->zf->mapping,
						    i >> SECTOR_SHIFT);
		if (page && !PageUptodate(page)) {
			bio = bio_alloc_bioset(cmd->zf->bdev, 1, REQ_OP_READ,
					       GFP_KERNEL, &cmd->zf->bioset);
			BUG_ON(!bio);
			bio_add_page(bio, page, PAGE_SIZE, 0);
			bio_clear_flag(bio, BIO_NO_PAGE_REF);
			bio->bi_iter.bi_sector = i >> SECTOR_SHIFT;
			bio->bi_end_io = zfile_read_endio;
			PRINT_DEBUG("Submit BIO [ra] %ld", i);
			submit_bio(bio);
		} else {
			if (page) {
				unlock_page(page);
				put_page(page);
			}
			break;
		}
	}

	mempool_free(cmd, &cmd->zf->cmdpool);
}

static int zfile_bioremap(IFile *ctx, struct bio *bio, struct dm_dev **dm_dev,
			  unsigned int nr)
{
	struct zfile *zf = (struct zfile *)ctx;
	loff_t offset = bio->bi_iter.bi_sector;
	size_t count = bio_sectors(bio);

	struct decompress_work *cmd;
	struct page *page;
	struct compressed_page_list *cpl, *next;
	struct bio *cbio;

	size_t start_idx, end_idx, begin, range, left, right, i;
	loff_t page_nr;
	size_t bs;

	if (unlikely(nr != 1 || !dm_dev[0])) {
		PRINT_ERROR("ZFile: nr wrong\n");
		PRINT_ERROR("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__,
			    __LINE__, bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if (unlikely(bio_op(bio) != REQ_OP_READ)) {
		PRINT_ERROR("ZFile: REQ not read\n");
		PRINT_ERROR("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__,
			    __LINE__, bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if (unlikely((offset << SECTOR_SHIFT) >= zf->header.vsize)) {
		PRINT_ERROR("ZFile: %lld over tail\n", offset);
		PRINT_ERROR("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__,
			    __LINE__, bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}
	if (unlikely(((offset + count) << SECTOR_SHIFT) > zf->header.vsize)) {
		PRINT_ERROR("ZFile: %lld over tail\n", offset);
		PRINT_ERROR("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__,
			    __LINE__, bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}

	bs = zf->header.opt.block_size;

	start_idx = (offset << SECTOR_SHIFT) / bs;
	end_idx = ((offset + count - 1) << SECTOR_SHIFT) / bs;

	begin = zf->jump[start_idx].partial_offset;
	range = zf->jump[end_idx].partial_offset + zf->jump[end_idx].delta -
		begin;
	left = begin & PAGE_MASK;
	right = (begin + range + PAGE_SIZE - 1) & PAGE_MASK;
	page_nr = (right - left) >> PAGE_SHIFT;

	LIST_HEAD(list);

	PRINT_DEBUG("Try grab %lu %lld", left, page_nr);

	bool slowpath = false;

	for (i = left; i < right; i += PAGE_SIZE) {
		page = zfile_grab_cache_page_nowait(zf->mapping,
						    i >> SECTOR_SHIFT);
		if (!page || !PageUptodate(page)) {
			if (page) {
				cbio = bio_alloc_bioset(zf->bdev, 1,
							REQ_OP_READ, GFP_NOIO,
							&zf->bioset);
				BUG_ON(!cbio);
				bio_add_page(cbio, page, PAGE_SIZE, 0);
				bio_set_flag(bio, BIO_NO_PAGE_REF);
				cbio->bi_iter.bi_sector = i >> SECTOR_SHIFT;
				cbio->bi_end_io = zfile_read_endio;
				PRINT_DEBUG("Submit BIO [fast] %lu", i);
				submit_bio(cbio);
			}
			slowpath = true;
		} else {
			unlock_page(page);
			cpl = kmalloc(sizeof(struct compressed_page_list),
				      GFP_NOIO);
			BUG_ON(!cpl);
			cpl->page = page;
			list_add_tail(&cpl->list, &list);
		}
	}

	if (slowpath)
		goto slow_path;

	PRINT_DEBUG("Fast path %lu %lld", left, page_nr);

	do_decompress(zf, bio, left, page_nr, &list, GFP_NOIO);

	goto out;

slow_path:
	PRINT_DEBUG("Slow path %lu %lld", left, page_nr);
	cmd = mempool_alloc(&zf->cmdpool, GFP_NOIO);

	INIT_WORK(&cmd->work, decompress_slowpath);
	cmd->bio = bio;
	cmd->zf = zf;

	BUG_ON(!queue_work(get_ovbd_context()->wq, &cmd->work));

out:
	list_for_each_entry_safe (cpl, next, &list, list) {
		put_page(cpl->page);
		list_del(&cpl->list);
		kfree(cpl);
	}

	return DM_MAPIO_SUBMITTED;
}

IFile *zfile_open_by_file(struct vfile *file, struct block_device *bdev)
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

	ret = mempool_init_kmalloc_pool(&zfile->cmdpool, 4096,
					sizeof(struct decompress_work));
	if (ret)
		goto error_out;

	ret = bioset_init(&zfile->bioset, 4096, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto error_out;

	zfile->c = dm_bufio_client_create(bdev, 4096, 2, 0, NULL, NULL);
	if (IS_ERR(zfile->c))
		goto error_out;

	zfile->mapping = bdev->bd_inode->i_mapping;
	zfile->bdev = bdev;

	return (IFile *)zfile;

error_out:
	if (zfile) {
		mempool_exit(&zfile->cmdpool);
		zfile_close((struct vfile *)zfile);
	}
	return NULL;
}

static void zfile_close(struct vfile *f)
{
	struct zfile *zfile = (struct zfile *)f;

	PRINT_INFO("close(%p)", (void *)f);
	if (zfile) {
		if (zfile->jump) {
			vfree(zfile->jump);
			zfile->jump = NULL;
		}
		zfile->fp = NULL;
		bioset_exit(&zfile->bioset);
		mempool_exit(&zfile->cmdpool);
		dm_bufio_client_destroy(zfile->c);
		kfree(zfile);
	}
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
