#include <asm/segment.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/lz4.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "lsmt.h"
#include "zfile.h"

static const size_t INFILE_BIO_POOL_SIZE = 256;
static const uint64_t INVALID_OFFSET = (1UL << 50) - 1;
static const uint32_t HT_SPACE = 4096;
static uint64_t *MAGIC0 = (uint64_t *)"LSMT\0\1\2";
static const uuid_t MAGIC1 = UUID_INIT(0x657e63d2, 0x9444, 0x084c, 0xa2, 0xd2,
				       0xc8, 0xec, 0x4f, 0xcf, 0xae, 0x8a);

static uint64_t segment_end(const struct segment_mapping *s)
{
	return s->offset + s->length;
}

void forward_offset_to(struct segment_mapping *s, uint64_t x)
{
	uint64_t delta = x - s->offset;
	s->offset = x;
	s->length -= delta;
	s->moffset += s->zeroed ? 0 : delta;
}

void backward_end_to(struct segment_mapping *s, uint64_t x)
{
	s->length = x - s->offset;
}

static void trim_edge(struct segment_mapping *pm, size_t m,
		      const struct segment_mapping *s)
{
	struct segment_mapping *back;
	if (m == 0)
		return;
	if (pm[0].offset < s->offset)
		forward_offset_to(&pm[0], s->offset);

	// back may be pm[0], when m == 1
	back = &pm[m - 1];
	if (segment_end(back) > segment_end(s))
		backward_end_to(back, segment_end(s));
}

const struct segment_mapping *
ro_index_lower_bound(const struct lsmt_ro_index *index, uint64_t offset)
{
	const struct segment_mapping *l = index->pbegin;
	const struct segment_mapping *r = index->pend - 1;
	const struct segment_mapping *pret;
	int ret = -1;
	while (l <= r) {
		int m = ((l - index->pbegin) + (r - index->pbegin)) >> 1;
		const struct segment_mapping *cmp = index->pbegin + m;
		if (offset >= segment_end(cmp)) {
			ret = m;
			l = index->pbegin + (m + 1);
		} else {
			r = index->pbegin + (m - 1);
		}
	}
	pret = index->pbegin + (ret + 1);
	if (pret >= index->pend) {
		return index->pend;
	} else {
		return pret;
	}
}

int ro_index_lookup(const struct lsmt_ro_index *index,
		    const struct segment_mapping *query_segment,
		    struct segment_mapping *ret_mappings, size_t n)
{
	int cnt = 0;
	const struct segment_mapping *lb;
	const struct segment_mapping *it;

	if (query_segment->length == 0)
		return 0;
	lb = ro_index_lower_bound(index, query_segment->offset);
	for (it = lb; it != index->pend; it++) {
		if (it->offset >= segment_end(query_segment))
			break;
		ret_mappings[cnt++] = *it;
		if (cnt == n)
			break;
	}
	if (cnt == 0)
		return 0;
	trim_edge(ret_mappings, cnt, query_segment);
	return cnt;
}

size_t ro_index_size(const struct lsmt_ro_index *index)
{
	return index->pend - index->pbegin;
}

static bool is_aligned(uint64_t val)
{
	return 0 == (val & 0x1FFUL);
}

int lsmt_bioremap(struct vfile *ctx, struct bio *bio, struct dm_dev **dev,
		  unsigned nr)
{
	struct lsmt_file *fp = (struct lsmt_file *)ctx;
	struct segment_mapping s;
	struct segment_mapping m[16];
	struct bio *subbio;
	size_t i = 0;
	loff_t offset = bio->bi_iter.bi_sector;
	if (bio_op(bio) != REQ_OP_READ) {
		return DM_MAPIO_KILL;
	}

	if ((offset << SECTOR_SHIFT) > fp->ht.virtual_size) {
		pr_info("LSMT: %lld over tail\n", offset);
		return DM_MAPIO_KILL;
	}

	// till here, take this bio, assume it will be submitted

	// actually, split bio by segment, summit and call endio when all split bio
	// are done

	s.offset = bio->bi_iter.bi_sector;
	s.length = bio_sectors(bio);
	while (true) {
		int n = ro_index_lookup(&fp->index, &s, m, 16);
		for (i = 0; i < n; ++i) {
			if (s.offset < m[i].offset) {
				// hole
				if (m[i].length < s.length) {
					subbio = bio_split(
						bio, m[i].offset - s.offset,
						GFP_NOIO, &fp->bioset);
					zero_fill_bio(subbio);
					bio_endio(subbio);
				} else {
					zero_fill_bio(bio);
					bio_endio(bio);
					return DM_MAPIO_SUBMITTED;
				}
			}
			// zeroe block
			if (m[i].zeroed) {
				if (m[i].length < s.length) {
					subbio = bio_split(bio, m[i].length,
							   GFP_NOIO,
							   &fp->bioset);
					zero_fill_bio(subbio);
					bio_endio(subbio);
				} else {
					zero_fill_bio(bio);
					bio_endio(bio);
					return DM_MAPIO_SUBMITTED;
				}
			} else {
				bio_set_dev(bio, dev[m[i].tag]->bdev);
				if (m[i].length < s.length) {
					subbio = bio_split(bio, m[i].length,
							   GFP_NOIO,
							   &fp->bioset);
					subbio->bi_iter.bi_sector =
						m[i].moffset;
					submit_bio(subbio);
				} else {
					bio->bi_iter.bi_sector = m[i].moffset;
					submit_bio(bio);
					return DM_MAPIO_SUBMITTED;
				}
			}
			forward_offset_to(&s, segment_end(&(m[i])));
		}
		if (n < 16)
			break;
	}
	if (s.length > 0) {
		zero_fill_bio(bio);
		bio_endio(bio);
	}
	return DM_MAPIO_SUBMITTED;
}

ssize_t lsmt_read(struct vfile *ctx, void *buf, size_t count, loff_t offset)
{
	struct lsmt_file *fp = (struct lsmt_file *)ctx;
	struct segment_mapping s;
	struct segment_mapping *m;
	ssize_t ret = 0;
	size_t i = 0;
	if (!is_aligned(offset | count)) {
		pr_info("LSMT: %lld %lu not aligned\n", offset, count);
		return -EINVAL;
	}
	if (offset > fp->ht.virtual_size) {
		pr_info("LSMT: %lld over tail\n", offset);
		return 0;
	}
	if (offset + count > fp->ht.virtual_size) {
		pr_info("LSMT: %lld %lu over tail\n", offset, count);
		count = fp->ht.virtual_size - offset;
	}
	m = kmalloc(16 * sizeof(struct segment_mapping), GFP_NOIO);
	s.offset = offset / SECTOR_SIZE;
	s.length = count / SECTOR_SIZE;
	while (true) {
		int n = ro_index_lookup(&fp->index, &s, m, 16);
		for (i = 0; i < n; ++i) {
			if (s.offset < m[i].offset) {
				// hole
				memset(buf, 0,
				       (m->offset - s.offset) * SECTOR_SIZE);
				offset +=
					(m[i].offset - s.offset) * SECTOR_SIZE;
				buf += (m[i].offset - s.offset) * SECTOR_SIZE;
				ret += (m[i].offset - s.offset) * SECTOR_SIZE;
			}
			// zeroe block
			if (m[i].zeroed) {
				memset(buf, 0, m->length * SECTOR_SIZE);
				offset += m[i].length * SECTOR_SIZE;
				buf += m[i].length * SECTOR_SIZE;
				ret += m[i].length * SECTOR_SIZE;
			} else {
				ssize_t dc = fp->fp->op->pread(
					fp->fp, buf, m->length * SECTOR_SIZE,
					m->moffset * SECTOR_SIZE);
				if (dc <= 0) {
					pr_info("LSMT: read failed ret=%ld\n",
						dc);
					goto out;
				}
				offset += m[i].length * SECTOR_SIZE;
				buf += m[i].length * SECTOR_SIZE;
				ret += m[i].length * SECTOR_SIZE;
			}
			forward_offset_to(&s, segment_end(&(m[i])));
		}
		if (n < 16)
			break;
	}
	if (s.length > 0) {
		memset(buf, 0, s.length * SECTOR_SIZE);
		offset += s.length * SECTOR_SIZE;
		ret += s.length * SECTOR_SIZE;
		buf += s.length * SECTOR_SIZE;
	}
out:
	kfree(m);
	return ret;
}

size_t lsmt_len(struct vfile *fp)
{
	return ((struct lsmt_file *)fp)->ht.virtual_size;
}

bool is_lsmtfile(struct vfile *fp)
{
	struct lsmt_ht ht;
	ssize_t ret;
	if (!fp)
		return false;

	pr_info("LSMT: read header\n");
	ret = fp->op->pread(fp, &ht, sizeof(struct lsmt_ht), 0);

	if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
		printk("failed to load header \n");
		return NULL;
	}

	return ht.magic0 == *MAGIC0 && uuid_equal(&ht.magic1, &MAGIC1);
}

void lsmt_close(struct vfile *ctx)
{
	struct lsmt_file *fp = (struct lsmt_file *)ctx;
	if (fp->ownership)
		fp->fp->op->close(fp->fp);
	vfree(fp->index.mapping);
	bioset_exit(&fp->bioset);
	kfree(fp);
}

// TODO: load multiple layer index
// static int merge_indexes(int level, struct lsmt_ro_index **indexes, size_t n,
//                          struct segment_mapping *mappings[], size_t *size,
//                          size_t *capacity, uint64_t start, uint64_t end) {
//     return -ENOSYS;
// }

// static struct lsmt_ro_index *merge_memory_indexes(
//     struct lsmt_ro_index **indexes, size_t n) {
//     return NULL;
// }

static struct vfile_op lsmt_ops = { .len = lsmt_len,
				    .pread = lsmt_read,
				    .pread_async = NULL,
				    .close = lsmt_close,
				    .bio_remap = lsmt_bioremap };

static ssize_t lsmt_load_index(struct vfile *fp, struct segment_mapping *p,
			       ssize_t index_size, loff_t index_offset)
{
	ssize_t ret;
	ssize_t idx;
	ssize_t index_bytes = index_size * sizeof(struct segment_mapping);
	pr_info("LSMT: loadindex off: %lld cnt: %ld\n", index_offset,
		index_bytes);
	ret = fp->op->pread(fp, p, index_bytes, index_offset);
	pr_info("LSMT: load index ret=%ld\n", ret);
	if (ret < index_bytes) {
		printk("failed to read index\n");
		return -1;
	}
	ret = 0;
	for (idx = 0; idx < index_size; idx++) {
		if (p[idx].offset != INVALID_OFFSET) {
			p[ret] = p[idx];
			p[ret].tag = 0;
			ret++;
		}
	}
	return ret;
}

static ssize_t lsmt_load_ht(struct vfile *fp, struct lsmt_ht *ht)
{
	ssize_t file_size;
	loff_t tailer_offset;
	ssize_t ret;
	if (!is_lsmtfile(fp)) {
		pr_info("LSMT: fp is not a lsmtfile\n");
		return -1;
	}
	file_size = fp->op->len(fp);
	tailer_offset = file_size - HT_SPACE;
	pr_info("LSMT: read tailer\n");
	ret = fp->op->pread(fp, ht, sizeof(struct lsmt_ht), tailer_offset);
	if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
		printk("failed to load tailer \n");
		return -1;
	}
	return 0;
}

struct lsmt_file *lsmt_open_ro(struct vfile *fp, bool ownership)
{
	struct segment_mapping *p = NULL;
	struct lsmt_file *lf = NULL;
	ssize_t cnt = 0;
	ssize_t index_bytes;

	if (!fp) {
		pr_info("LSMT: failed to open zfile\n");
		return NULL;
	}

	lf = kzalloc(sizeof(struct lsmt_file), GFP_KERNEL);
	if (!lf)
		goto error_out;
	lf->fp = fp;
	lf->ownership = ownership;

	cnt = lsmt_load_ht(fp, &lf->ht);
	if (cnt < 0) {
		goto error_out;
	}

	index_bytes = lf->ht.index_size * sizeof(struct segment_mapping);
	pr_info("LSMT: off: %lld, bytes: %ld\n", lf->ht.index_offset,
		index_bytes);
	if (index_bytes == 0 || index_bytes > 1024UL * 1024 * 1024)
		return NULL;
	p = vmalloc(index_bytes);

	cnt = lsmt_load_index(fp, p, lf->ht.index_size, lf->ht.index_offset);
	if (cnt < 0) {
		goto error_out;
	}

	lf->ht.index_size = cnt;
	lf->index.mapping = p;
	lf->index.pbegin = p;
	lf->index.pend = p + cnt;
	pr_info("LSMT: index_size=%lu\n", cnt);
	lf->vfile.op = &lsmt_ops;
	bioset_init(&lf->bioset, INFILE_BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
	return lf;

error_out:
	vfree(p);
	kfree(lf);
	if (ownership)
		fp->op->close(fp);
	return NULL;
}

// TODO: load multiple layer index
// struct lsmt_file *lsmt_open_merge(struct vfile *lf, int n) {
//     return NULL;
// }