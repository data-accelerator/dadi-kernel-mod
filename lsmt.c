#include <asm/segment.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/lz4.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include "lsmt.h"
#include "zfile.h"
#include "log-format.h"

#define REVERSE_LIST(type, begin, back)                                        \
	{                                                                      \
		type *l = (begin);                                             \
		type *r = (back);                                              \
		while (l < r) {                                                \
			type tmp = *l;                                         \
			*l = *r;                                               \
			*r = tmp;                                              \
			l++;                                                   \
			r--;                                                   \
		}                                                              \
	}

#define UINT64_MAX 0xFFFFFFFFFFFFFFFFULL
#define ALIGNMENT 512U

#define TYPE_SEGMENT 0
#define TYPE_SEGMENT_MAPPING 1
#define TYPE_FILDES 2
#define TYPE_LSMT_RO_INDEX 3

static const size_t INFILE_BIO_POOL_SIZE = 256;
static const uint64_t INVALID_OFFSET = (1UL << 50) - 1;
static const uint32_t HT_SPACE = 4096;
static const uint32_t ALIGNMENT4K = 4 << 10;
static uint64_t *MAGIC0 = (uint64_t *)"LSMT\0\1\2";
static const uuid_t MAGIC1 = UUID_INIT(0x657e63d2, 0x9444, 0x084c, 0xa2, 0xd2,
				       0xc8, 0xec, 0x4f, 0xcf, 0xae, 0x8a);

static struct segment_mapping INVALID_MAPPING = { INVALID_OFFSET, 0, 0, 0, 0 };

size_t lsmt_len(IFile *fp);
ssize_t lsmt_read(IFile *ctx, void *buf, size_t count, loff_t offset);
void lsmt_close(IFile *ctx);
int lsmt_bioremap(IFile *ctx, struct bio *bio, struct dm_dev **dev,
		  unsigned nr);

static struct vfile_op lsmt_ops = { .len = lsmt_len,
				    .pread = lsmt_read,
				    .pread_async = NULL,
				    .close = lsmt_close,
				    .bio_remap = lsmt_bioremap };

static uint64_t segment_end(const void *s)
{
	return ((struct segment *)s)->offset + ((struct segment *)s)->length;
}

void forward_offset_to(void *m, uint64_t x, int8_t type)
{
	struct segment *s = (struct segment *)m;
	uint64_t delta = x - s->offset;
	s->offset = x;
	s->length -= delta;
	if (type == TYPE_SEGMENT_MAPPING) {
		struct segment_mapping *tmp = (struct segment_mapping *)m;
		if (!tmp->zeroed) {
			tmp->moffset += delta;
		}
	}
}

void backward_end_to(void *m, uint64_t x)
{
	struct segment *s = (struct segment *)m;
	s->length = x - s->offset;
}

static void trim_edge(void *m, const struct segment *bound_segment,
		      uint8_t type)
{
	if (((struct segment *)m)->offset < bound_segment->offset) {
		forward_offset_to(m, bound_segment->offset, type);
	}
	if (segment_end(m) > segment_end(bound_segment)) {
		backward_end_to(m, segment_end(bound_segment));
	}
}

// static void trim_edge(struct segment_mapping *pm, size_t m,
// 		      const struct segment_mapping *s)
// {
// 	struct segment_mapping *back;
// 	if (m == 0)
// 		return;
// 	if (pm[0].offset < s->offset)
// 		forward_offset_to(&pm[0], s->offset);

// 	// back may be pm[0], when m == 1
// 	back = &pm[m - 1];
// 	if (segment_end(back) > segment_end(s))
// 		backward_end_to(back, segment_end(s));
// }

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
		    const struct segment *query_segment,
		    struct segment_mapping *ret_mappings, size_t n)
{
	if (query_segment->length == 0)
		return 0;
	const struct segment_mapping *lb =
		ro_index_lower_bound(index, query_segment->offset);
	int cnt = 0;
	for (const struct segment_mapping *it = lb; it != index->pend; it++) {
		if (it->offset >= segment_end(query_segment))
			break;
		ret_mappings[cnt++] = *it;
		if (cnt == n)
			break;
	}
	if (cnt == 0)
		return 0;
	trim_edge(&ret_mappings[0], query_segment, TYPE_SEGMENT_MAPPING);
	if (cnt > 1) {
		trim_edge(&ret_mappings[cnt - 1], query_segment,
			  TYPE_SEGMENT_MAPPING);
	}
	return cnt;
}

size_t ro_index_size(const struct lsmt_ro_index *index)
{
	return index->pend - index->pbegin;
}

struct lsmt_ro_index *
create_memory_index(const struct segment_mapping *pmappings, size_t n,
		    uint64_t moffset_begin, uint64_t moffset_end, bool copy)
{
	// bool ok0 = verify_mapping_order(pmappings, n);
	// bool ok1 = verify_mapping_moffset(pmappings, n,
	//                                  moffset_begin, moffset_end);
	struct lsmt_ro_index *ret = NULL;
	// if (ok0 & ok1) {
	int index_size = sizeof(struct lsmt_ro_index);
	if (copy) {
		index_size += sizeof(struct segment_mapping) * n;
	}
	ret = (struct lsmt_ro_index *)kmalloc(index_size, GFP_KERNEL);
	if (!ret) {
		PRINT_ERROR("malloc memory failed");
		return NULL;
	}
	if (!copy) {
		ret->pbegin = pmappings;
		ret->pend = pmappings + n;
	} else {
		memcpy(ret->mapping, pmappings,
		       n * sizeof(struct segment_mapping));
		ret->pbegin = ret->mapping;
		ret->pend = ret->mapping + n;
	}
	PRINT_INFO("create memory index done. {index_count: %lu, memcopy: %d}",
		   n, copy);
	return ret;
};

static bool is_aligned(uint64_t val)
{
	return 0 == (val & 0x1FFUL);
}

int lsmt_bioremap(IFile *ctx, struct bio *bio, struct dm_dev **dev, unsigned nr)
{
	struct lsmt_ro_file *fp = (struct lsmt_ro_file *)ctx;
	struct segment s;
	struct segment_mapping m[16];
	struct bio *subbio;
	size_t i = 0;
	loff_t offset = bio->bi_iter.bi_sector;
	if (bio_op(bio) != REQ_OP_READ) {
		return DM_MAPIO_KILL;
	}

	if ((offset << SECTOR_SHIFT) > fp->ht.virtual_size) {
		PRINT_INFO("LSMT: %lld over tail\n", offset);
		return DM_MAPIO_KILL;
	}

	// till here, take this bio, assume it will be submitted

	// actually, split bio by segment, summit and call endio when all split bio
	// are done

	s.offset = bio->bi_iter.bi_sector;
	s.length = bio_sectors(bio);
	while (true) {
		int n = ro_index_lookup(fp->index, &s, m, 16);
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
			forward_offset_to(&s, segment_end(&(m[i])),
					  TYPE_SEGMENT);
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

size_t lsmt_len(IFile *fp)
{
	return ((struct lsmt_ro_file *)fp)->ht.virtual_size;
}

ssize_t lsmt_read(IFile *ctx, void *buf, size_t count, loff_t offset)
{
	struct lsmt_ro_file *lsmt_file = (struct lsmt_ro_file *)ctx;
	struct segment s;
	struct segment_mapping *m;
	ssize_t ret = 0;
	size_t i = 0;
	if (!is_aligned(offset | count)) {
		PRINT_ERROR("LSMT: %lld %lu not aligned\n", offset, count);
		return -EINVAL;
	}
	if (offset > lsmt_file->ht.virtual_size) {
		PRINT_INFO("LSMT: %lld over tail\n", offset);
		return 0;
	}
	if (offset + count > lsmt_file->ht.virtual_size) {
		PRINT_INFO("LSMT: %lld %lu over tail\n", offset, count);
		count = lsmt_file->ht.virtual_size - offset;
	}
	m = kmalloc(16 * sizeof(struct segment_mapping), GFP_NOIO);
	s.offset = offset / SECTOR_SIZE;
	s.length = count / SECTOR_SIZE;
	while (true) {
		int n = ro_index_lookup(lsmt_file->index, &s, m, 16);
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
				int layer_id = m[i].tag;
				ssize_t dc = lsmt_file->fp[layer_id]->op->pread(
					lsmt_file->fp[layer_id], buf,
					m->length * SECTOR_SIZE,
					m->moffset * SECTOR_SIZE);
				if (dc <= 0) {
					PRINT_INFO(
						"LSMT: read failed ret=%ld\n",
						dc);
					goto out;
				}
				offset += m[i].length * SECTOR_SIZE;
				buf += m[i].length * SECTOR_SIZE;
				ret += m[i].length * SECTOR_SIZE;
			}
			forward_offset_to(&s, segment_end(&(m[i])),
					  TYPE_SEGMENT);
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

bool is_lsmtfile(IFile *fp)
{
	struct lsmt_ht ht;
	ssize_t ret;
	if (!fp)
		return false;

	PRINT_INFO("LSMT: read header(IFile: %x)", fp);
	ret = fp->op->pread(fp, &ht, sizeof(struct lsmt_ht), 0);

	if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
		PRINT_ERROR("failed to load header");
		return NULL;
	}

	return ht.magic0 == *MAGIC0 && uuid_equal(&ht.magic1, &MAGIC1);
}

void lsmt_close(IFile *ctx)
{
	struct lsmt_ro_file *lsmt_file = (struct lsmt_ro_file *)ctx;
	if (lsmt_file->ownership) {
		for (int i = 0; i < lsmt_file->nr; i++) {
			lsmt_file->fp[i]->op->close(lsmt_file->fp[i]);
		}
	}
	vfree(lsmt_file->index->mapping);
	bioset_exit(&lsmt_file->bioset);
	kfree(lsmt_file);
}

static int merge_indexes(int level, struct lsmt_ro_index **indexes, size_t n,
			 struct segment_mapping *mappings[], size_t *size,
			 size_t *capacity, uint64_t start, uint64_t end)
{
	if (level >= n) {
		return 0;
	}
	struct segment_mapping *p =
		(struct segment_mapping *)ro_index_lower_bound(indexes[level],
							       start);
	const struct segment_mapping *pend = indexes[level]->pend;
	if (p == pend) {
		merge_indexes(level + 1, indexes, n, mappings, size, capacity,
			      start, end);
		return 0;
	}
	struct segment_mapping it = *p;
	if (start > it.offset) {
		forward_offset_to(&it, start, TYPE_SEGMENT_MAPPING);
	}
	while (p != pend) {
		if (end <= it.offset)
			break;
		if (start < it.offset) {
			merge_indexes(level + 1, indexes, n, mappings, size,
				      capacity, start, it.offset);
		}
		if (end < segment_end(&it)) {
			backward_end_to(&it, end);
		}
		if (*size == *capacity) {
			size_t tmp = (*capacity) << 1;
			PRINT_INFO("realloc array. ( %lu -> %lu )", *capacity,
				   tmp);
			struct segment_mapping *m =
				(struct segment_mapping *)kmalloc(
					tmp * sizeof(struct segment_mapping),
					GFP_KERNEL);
			if (m == NULL) {
				PRINT_ERROR("realloc failed.");
				return -1;
			}
			memcpy(m, *mappings,
			       *capacity * sizeof(struct segment_mapping));
			*mappings = m;
			*capacity = tmp;
		}
		it.tag = level;
		(*mappings)[*size] = it;
		(*size)++;
		start = segment_end(p);
		// PRINT_DEBUG("push segment %d {offset: %lu, len: %lu}",
		// 	*size, p->offset, p->length);
		p++;
		it = *p;
	}
	if (start < end) {
		merge_indexes(level + 1, indexes, n, mappings, size, capacity,
			      start, end);
	}
	return 0;
}

static struct lsmt_ro_index *
merge_memory_indexes(struct lsmt_ro_index **indexes, size_t n)
{
	size_t size = 0;
	size_t capacity = ro_index_size(indexes[0]);
	PRINT_DEBUG("init capacity: %ld\n", capacity);
	struct lsmt_ro_index *ret = NULL;
	struct segment_mapping *mappings = (struct segment_mapping *)kmalloc(
		sizeof(struct segment_mapping) * capacity, GFP_KERNEL);
	if (!mappings) {
		goto err_ret;
	}
	PRINT_DEBUG("start merge indexes, layers: %d", n);
	merge_indexes(0, indexes, n, &mappings, &size, &capacity, 0,
		      UINT64_MAX);
	PRINT_INFO("merge done, index size: %lu", size);
	ret = (struct lsmt_ro_index *)kmalloc(sizeof(struct lsmt_ro_index),
					      GFP_KERNEL);
	struct segment_mapping *tmp = (struct segment_mapping *)kmalloc(
		size * sizeof(struct segment_mapping), GFP_KERNEL);
	memcpy(tmp, mappings, size * sizeof(struct segment_mapping));
	kfree(mappings);
	if (!tmp || !ret)
		goto err_ret;
	ret->pbegin = tmp;
	ret->pend = tmp + size;
	PRINT_INFO("ret index done. size: %lu", size);
	return ret;

err_ret:
	kfree(mappings);
	kfree(ret);
	kfree(tmp);
	return NULL;
}

static ssize_t do_load_index(IFile *fp, struct segment_mapping *p,
			     struct lsmt_ht *ht)
{
	ssize_t index_bytes = ht->index_size * sizeof(struct segment_mapping);
	PRINT_INFO("LSMT: loadindex off: %lld cnt: %ld", ht->index_offset,
		   ht->index_size);
	ssize_t readn = fp->op->pread(fp, p, index_bytes, ht->index_offset);
	if (readn < index_bytes) {
		PRINT_ERROR("failed to read index");
		return -1;
	}
	size_t valid = 0;
	for (off_t idx = 0; idx < ht->index_size; idx++) {
		if (p[idx].offset != INVALID_OFFSET) {
			p[valid] = p[idx];
			p[valid].tag = 0;
			PRINT_DEBUG("valid index %d {offset: %lu, length: %lu}",
				    valid, p[idx].offset, p[idx].length);
			valid++;
		}
	}
	PRINT_INFO("valid index count: %ld", valid);
	ht->index_size = valid;
	return 0;
}

static ssize_t lsmt_load_ht(IFile *fp, struct lsmt_ht *ht)
{
	ssize_t file_size;
	loff_t tailer_offset;
	ssize_t ret;
	if (!is_lsmtfile(fp)) {
		PRINT_INFO("LSMT: fp is not a lsmtfile(%x)\n", fp);
		return -1;
	}
	file_size = fp->op->len(fp);
	tailer_offset = file_size - HT_SPACE;
	ret = fp->op->pread(fp, ht, sizeof(struct lsmt_ht), tailer_offset);
	if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
		PRINT_ERROR("failed to load tailer(%x)\n", fp);
		return -1;
	}
	PRINT_INFO("LSMT(%x), index_offset %lu: index_count: %lu", fp,
		   ht->index_offset, ht->index_size);

	return 0;
}

static struct lsmt_ro_index *load_merge_index(IFile *files[], size_t n,
					      struct lsmt_ht *ht)
{
	struct lsmt_ro_index *indexes[OVBD_MAX_LAYERS];
	struct lsmt_ro_index *pmi = NULL;
	if (n > OVBD_MAX_LAYERS) {
		PRINT_ERROR("too many indexes to merge, %d at most!",
			    OVBD_MAX_LAYERS);
		return NULL;
	}
	for (int i = 0; i < n; ++i) {
		PRINT_INFO("read %d-th LSMT info", i);
		ssize_t size = 0;
		// struct lsmt_ht ht;
		ssize_t ok = lsmt_load_ht(files[i], ht);
		size_t index_bytes =
			ht->index_size * sizeof(struct segment_mapping);
		if (index_bytes == 0 || index_bytes > 1024UL * 1024 * 1024)
			return NULL;
		struct segment_mapping *p = vmalloc(index_bytes);
		if (do_load_index(files[i], p, ht) == -1) {
			vfree(p);
			PRINT_ERROR("failed to load index from %d-th file", i);
			return NULL;
		}
		struct lsmt_ro_index *pi = create_memory_index(
			p, ht->index_size, HT_SPACE / ALIGNMENT,
			ht->index_offset / ALIGNMENT, false);
		if (!pi) {
			PRINT_ERROR(
				"failed to create memory index! ( %d-th file )",
				i);
			vfree(p);
			return NULL;
		}
		indexes[i] = pi;
	}
	PRINT_INFO("reverse index.");
	REVERSE_LIST(IFile *, &files[0], &files[n - 1]);
	REVERSE_LIST(struct lsmt_ro_index *, &indexes[0], &indexes[n - 1]);

	pmi = merge_memory_indexes(&indexes[0], n);

	if (!pmi) {
		PRINT_ERROR("failed to merge indexes");
		goto error_ret;
	}
	PRINT_DEBUG("merge index done.");

	return pmi;

error_ret:
	return NULL;
}

struct lsmt_ro_file *lsmt_open_ro(IFile *fp, bool ownership)
{
	ssize_t cnt = 0;
	ssize_t index_bytes;

	if (!fp) {
		PRINT_INFO("LSMT: failed to open zfile(%x)\n", fp);
		return NULL;
	}
	size_t size = sizeof(struct lsmt_ro_file) + 2 * sizeof(IFile *);
	struct lsmt_ro_file *lf =
		(struct lsmt_ro_file *)kzalloc(size, GFP_KERNEL);
	if (!lf)
		goto error_out;
	lf->fp[0] = NULL;
	lf->fp[1] = fp;
	lf->ownership = ownership;

	cnt = lsmt_load_ht(fp, &lf->ht);
	if (cnt < 0) {
		goto error_out;
	}

	index_bytes = lf->ht.index_size * sizeof(struct segment_mapping);
	PRINT_INFO("LSMT: off: %lld, bytes: %ld", lf->ht.index_offset,
		   index_bytes);
	if (index_bytes == 0 || index_bytes > 1024UL * 1024 * 1024)
		return NULL;
	struct segment_mapping *p = vmalloc(index_bytes);
	cnt = do_load_index(fp, p, &lf->ht);
	if (cnt < 0) {
		goto error_out;
	}
	for (struct segment_mapping *it = &p[0]; it != p + lf->ht.index_size;
	     it++) {
		it->tag++;
	}
	lf->ht.index_size = cnt;
	lf->index =
		create_memory_index(p, lf->ht.index_size, HT_SPACE / ALIGNMENT,
				    lf->ht.index_offset / ALIGNMENT, false);
	PRINT_INFO("LSMT: index_size=%lu", cnt);
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
struct lsmt_ro_file *lsmt_open_files(IFile *zfiles[], int n)
{
	PRINT_INFO("LSMT open_files, layers: %d", n);
	struct lsmt_ro_file *ret = (struct lsmt_ro_file *)kmalloc(
		sizeof(IFile *) * n + sizeof(struct lsmt_ro_file), GFP_KERNEL);
	struct lsmt_ht ht;
	struct lsmt_ro_index *idx = load_merge_index(zfiles, n, &ht);
	if (idx == NULL) {
		PRINT_ERROR("load merge index failed.");
		kfree(ret);
		return NULL;
	}
	ret->nr = n;
	ret->index = idx;
	ret->ownership = true;
	ret->vfile.op = &lsmt_ops;
	ret->ht.virtual_size = ht.virtual_size;
	PRINT_DEBUG("ret->fp[0]: %x", &(ret->fp[0]));
	memcpy(&(ret->fp[0]), &zfiles[0], n * sizeof(IFile *));
	return ret;
}