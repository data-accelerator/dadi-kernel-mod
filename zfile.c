#include "zfile.h"

#include <linux/lz4.h>
#include <linux/vmalloc.h>
#include <linux/device-mapper.h>
#include <linux/prefetch.h>
#include "vfsfile.h"
#include "log-format.h"

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

enum zfile_page_state {
	ZFILE_PAGE_INPLACE = 0,
	ZFILE_PAGE_READING = 1,
	ZFILE_PAGE_UPTODATE = 2,
	ZFILE_PAGE_ERROR = 3,
};

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

static int zf_decompress(struct zfile *zf, struct page *page, loff_t offset,
			 void *holder, loff_t holder_off)
{
	void *dst = NULL;
	void *src = NULL;
	size_t idx, c_cnt;
	loff_t begin;
	int ret = 0;
	BUG_ON(!holder);

	idx = offset >> PAGE_SHIFT;
	begin = zf->jump[idx].partial_offset;
	c_cnt = zf->jump[idx].delta -
		(zf->header.opt.verify ? sizeof(uint32_t) : 0);

	dst = kmap_atomic(page);
	BUG_ON(!dst);
	src = holder + (begin - holder_off);
	prefetch_range(src, c_cnt);
	prefetchw(dst);

	ret = LZ4_decompress_safe(src, dst, c_cnt, PAGE_SIZE);

	kunmap_atomic(dst);

	if (ret < 0) {
		pr_err("Decompress error\n");
	}

	return ret;
}

struct decompress_work {
	struct work_struct work;
	struct zfile *zf;
	struct bio *bio;
	struct address_space *mapping;
	struct list_head pagelist;
};

struct compressed_page {
	struct list_head list;
	struct page *page;
	loff_t underlay_offset;
	unsigned long state;
};

static void do_decompress(struct zfile *zf, struct bio *bio,
			  struct address_space *mapping,
			  struct list_head *pagelist, size_t left, int nr)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	struct page **pages;
	struct compressed_page *cp;
	int i = 0;

	void *holder = NULL;

	pages = kmalloc_array(nr, sizeof(struct page *), GFP_KERNEL);

	list_for_each_entry (cp, pagelist, list) {
		pages[i++] = cp->page;
	}

	holder = vm_map_ram(pages, nr, -1);

	// now pages are referenced, will not release

	bio_for_each_segment (bv, bio, iter) {
		if (unlikely(zf_decompress(zf, bv.bv_page,
					   (iter.bi_sector << SECTOR_SHIFT) &
						   PAGE_MASK,
					   holder, left) < 0)) {
			pr_err("ZFile: error decompressing %llu\n",
			       (iter.bi_sector << SECTOR_SHIFT) & PAGE_MASK);
			bio_io_error(bio);
			break;
		}
	}

	vm_unmap_ram(holder, nr);

	bio_endio(bio);

	kfree(pages);
}

static void try_drop_cache(struct address_space *mapping, size_t begin,
			   size_t range, size_t left, size_t right)
{
#ifdef ZFILE_CLEANUP_CACHE
	if (begin + range == right) {
		right += PAGE_SHIFT;
	}
	if (right > left) {
		unmap_mapping_range(mapping, left >> PAGE_SHIFT,
				    right >> PAGE_SHIFT, 0);
	}
#endif
}

#define SetCP(cp, Key) set_bit(ZFILE_PAGE_##Key, &(cp)->state)
#define ClearCP(cp, Key) clear_bit(ZFILE_PAGE_##Key, &(cp)->state)
#define GetCP(cp, Key) test_bit(ZFILE_PAGE_##Key, &(cp)->state)

static void zfile_unlock_page(struct compressed_page *cp)
{
	if (GetCP(cp, INPLACE)) {
		clear_and_wake_up_bit(ZFILE_PAGE_READING, &cp->state);
	} else {
		unlock_page(cp->page);
	}
	detach_page_private(cp->page);
}

static void zfile_wait_on_compressed_page_locked(struct compressed_page *cp)
{
	if (GetCP(cp, INPLACE)) {
		wait_on_bit_io(&cp->state, ZFILE_PAGE_READING,
			       TASK_UNINTERRUPTIBLE);
	} else {
		wait_on_page_locked(cp->page);
	}
}

static void decompress_fn(struct work_struct *work)
{
	size_t start_idx, end_idx, begin, range, left, right;
	loff_t offset, count, nr;
	size_t bs;
	struct compressed_page *cp, *ncp;
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

	list_for_each_entry (cp, &cmd->pagelist, list) {
		zfile_wait_on_compressed_page_locked(cp);
		if (GetCP(cp, INPLACE)) {
			if (!GetCP(cp, UPTODATE)) {
				goto exit;
			}
		} else {
			if (!PageUptodate(cp->page)) {
				goto exit;
			}
		}
	}
	do_decompress(cmd->zf, cmd->bio, cmd->mapping, &cmd->pagelist, left,
		      nr);

	try_drop_cache(cmd->mapping, begin, range, left, right);
exit:
	list_for_each_entry_safe (cp, ncp, &cmd->pagelist, list) {
		if (!GetCP(cp, INPLACE))
			put_page(cp->page);
		mempool_free(cp, &cmd->zf->cppool);
	}
	mempool_free(cmd, &cmd->zf->cmdpool);
}

struct readahead_work {
	struct work_struct work;
	struct address_space *mapping;
	loff_t left;
	int nr;
};

void zfile_readahead(struct address_space *mapping, loff_t left, int nr)
{
#ifdef ZFILE_READAHEAD
	page_cache_readahead_unbounded(mapping, NULL, left >> PAGE_SHIFT, nr,
				       0);
#endif
}

static void zfile_readendio(struct bio *bio)
{
	struct bio_vec *bvec;
	blk_status_t err = bio->bi_status;
	struct bvec_iter_all iter_all;

	bio_for_each_segment_all (bvec, bio, iter_all) {
		struct page *page = bvec->bv_page;
		struct compressed_page *cp =
			(struct compressed_page *)page_private(page);

		/* page is already locked */
		BUG_ON(!page_has_private(page));

		if (GetCP(cp, INPLACE)) {
			BUG_ON(GetCP(cp, UPTODATE));
			if (err)
				SetCP(cp, ERROR);
			else
				SetCP(cp, UPTODATE);
		} else {
			BUG_ON(PageUptodate(page));
			if (err)
				SetPageError(page);
			else
				SetPageUptodate(page);
		}

		zfile_unlock_page(cp);
		/* page could be reclaimed now */
	}
	bio_put(bio);
}

static void list_move_all(struct list_head *old, struct list_head *new)
{
	struct list_head *first = old->next;
	struct list_head *last = old->prev;
	INIT_LIST_HEAD(old);
	first->prev = new;
	last->next = new;
	new->prev = last;
	new->next = first;
}

static bool zfile_able_to_inplace(struct zfile *zf, loff_t upper_offset,
				  loff_t read_offset)
{
	loff_t idx = (upper_offset) / zf->header.opt.block_size;
	return ((zf->jump[idx].partial_offset >> PAGE_SHIFT) > (read_offset));
}

static void zfile_acquire_pages(struct zfile *zf, struct block_device *bdev,
				struct address_space *mapping, struct bio *bio,
				struct list_head *pagelist, loff_t left,
				int nr_pages)
{
	int i, j, bpnr;
	struct compressed_page *cp;
	struct blk_plug plug;
	struct page **biopages;
	struct bio *cbio;
	struct bio_vec bv;
	struct bvec_iter iter;
	loff_t boff, bleft, bsize, bright, brange;

	boff = bio->bi_iter.bi_sector << SECTOR_SHIFT;
	bleft = boff & PAGE_MASK;
	bsize = bio->bi_iter.bi_size;
	bright = (boff + bsize + PAGE_SIZE - 1) & PAGE_MASK;
	brange = bright - bleft;
	biopages = kmalloc_array(brange >> PAGE_SHIFT, sizeof(struct page *),
				 GFP_NOIO);

	cbio = bio_clone_fast(bio, GFP_NOIO, &zf->bioset);
	bpnr = 0;
	bio_for_each_segment (bv, cbio, iter) {
		biopages[bpnr++] = bv.bv_page;
	}
	bio_put(cbio);

	blk_start_plug(&plug);

	for (i = 0, j = 0; i < nr_pages; i++) {
		cp = mempool_alloc(&zf->cppool, GFP_NOIO);
		list_add_tail(&cp->list, pagelist);
		cp->underlay_offset = left + (i << PAGE_SHIFT);
		cp->state = 0;
		cp->page = find_lock_page(mapping, i + (left >> PAGE_SHIFT));
		if (cp->page == NULL) {
			// not in page cache
			while (j < bpnr) {
				if (zfile_able_to_inplace(
					    zf, (j << PAGE_SHIFT) + bleft,
					    (i << PAGE_SHIFT) + left))
					break;
				j++;
			}
			if (j < bpnr && !page_has_private(biopages[j])) {
				SetCP(cp, INPLACE);
				test_and_set_bit_lock(ZFILE_PAGE_READING,
						      &cp->state);
				cp->page = biopages[j];
			} else {
				cp->page = find_or_create_page(
					mapping, i + (left >> PAGE_SHIFT),
					GFP_NOIO);
			}
		}
		BUG_ON(!cp->page);
		attach_page_private(cp->page, cp);
		if (GetCP(cp, INPLACE) || !PageUptodate(cp->page)) {
			struct bio *sbio =
				bio_alloc_bioset(GFP_NOIO, 1, &zf->bioset);
			BUG_ON(!sbio);
			bio_add_page(sbio, cp->page, PAGE_SIZE, 0);
			bio_set_dev(sbio, bdev);
			bio_set_op_attrs(sbio, REQ_OP_READ, 0);
			sbio->bi_iter.bi_sector =
				((i << PAGE_SHIFT) + left) >> SECTOR_SHIFT;
			sbio->bi_end_io = zfile_readendio;
			submit_bio(sbio);
		} else {
			zfile_unlock_page(cp);
		}
	}

	blk_finish_plug(&plug);
	kfree(biopages);
}

static int zfile_bioremap(IFile *ctx, struct bio *bio, struct dm_dev **dm_dev,
			  unsigned int nr)
{
	struct zfile *zf = (struct zfile *)ctx;
	loff_t offset = bio->bi_iter.bi_sector;
	size_t count = bio_sectors(bio);
	size_t bs = zf->header.opt.block_size;
	size_t start_idx, end_idx;
	loff_t begin, range, right, left, i;
	int nr_pages;
	struct decompress_work *cmd;
	struct compressed_page *cp;

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
	start_idx = (offset << SECTOR_SHIFT) / bs;
	end_idx = ((offset + count - 1) << SECTOR_SHIFT) / bs;

	begin = zf->jump[start_idx].partial_offset;
	range = zf->jump[end_idx].partial_offset + zf->jump[end_idx].delta -
		begin;
	left = begin & PAGE_MASK;
	right = (begin + range + PAGE_SIZE - 1) & PAGE_MASK;
	nr_pages = (right - left) >> PAGE_SHIFT;

	struct address_space *mapping = dm_dev[0]->bdev->bd_inode->i_mapping;

	LIST_HEAD(pagelist);

	zfile_acquire_pages(zf, dm_dev[0]->bdev, mapping, bio, &pagelist, left,
			    nr_pages);

	zfile_readahead(mapping, right, 64);

#ifdef ZFILE_DECOMPRESS_SHORTCUT
	// possable online decompress
	i = 0;
	bool miss = false;
	list_for_each_entry (cp, &pagelist, list) {
		if (!PageUptodate(cp->page)) {
			miss = true;
			break;
		}
	}

	if (likely(!miss)) {
		do_decompress(zf, bio, mapping, &pagelist, left, nr_pages);
		try_drop_cache(mapping, begin, range, left, right);
		return DM_MAPIO_SUBMITTED;
	}
#endif

	// missing pages exists, read & decompress in workers
	cmd = mempool_alloc(&zf->cmdpool, GFP_NOIO);

	INIT_WORK(&cmd->work, decompress_fn);
	cmd->bio = bio;
	cmd->zf = zf;
	cmd->mapping = mapping;
	list_move_all(&pagelist, &cmd->pagelist);

	BUG_ON(!queue_work(zf->wq, &cmd->work));

	return DM_MAPIO_SUBMITTED;
}

static struct vfile_op zfile_ops = { .len = zfile_len,
				     .pread = zfile_read,
				     .pread_async = NULL,
				     .bio_remap = zfile_bioremap,
				     .close = zfile_close };

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
					sizeof(struct zfile_ht), tailer_offset);
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

	ret = mempool_init_kmalloc_pool(&zfile->cppool, 4096,
					sizeof(struct compressed_page));
	if (ret)
		goto error_out;

	ret = bioset_init(&zfile->bioset, 4096, 0,
			  BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
	if (ret)
		goto error_out;

	zfile->onlinecpus = num_possible_cpus();
	const unsigned int flags =
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE;
	zfile->wq = alloc_workqueue("zfile_unzip", flags,
				    zfile->onlinecpus + zfile->onlinecpus / 4);
	if (IS_ERR(zfile->wq))
		goto error_out;

	return (IFile *)zfile;

error_out:
	if (zfile) {
		mempool_exit(&zfile->cppool);
		mempool_exit(&zfile->cmdpool);
		zfile_close((struct vfile *)zfile);
	}
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

void zfile_close(struct vfile *f)
{
	struct zfile *zfile = (struct zfile *)f;

	PRINT_INFO("close(%p)", (void *)f);
	if (zfile) {
		if (zfile->wq && !IS_ERR(zfile->wq)) {
			flush_workqueue(zfile->wq);
			destroy_workqueue(zfile->wq);
			zfile->wq = NULL;
		}
		if (zfile->jump) {
			vfree(zfile->jump);
			zfile->jump = NULL;
		}
		zfile->fp = NULL;
		bioset_exit(&zfile->bioset);
		mempool_exit(&zfile->cppool);
		mempool_exit(&zfile->cmdpool);
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
