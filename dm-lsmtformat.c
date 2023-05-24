// SPDX-License-Identifier: GPL-2.0

#include "dm-ovbd.h"
#include <linux/vmalloc.h>

#define REVERSE_ARRAY(type, begin, back) \
	{                                \
		type *l = (begin);       \
		type *r = (back);        \
		while (l < r) {          \
			type tmp = *l;   \
			*l = *r;         \
			*r = tmp;        \
			l++;             \
			r--;             \
		}                        \
	}

#define UINT64_MAX 0xFFFFFFFFFFFFFFFFULL
#define ALIGNMENT 512U

#define TYPE_SEGMENT 0
#define TYPE_SEGMENT_MAPPING 1
#define TYPE_FILDES 2
#define TYPE_LSMT_RO_INDEX 3

#define OVBD_MAX_LAYERS 256

static const u64 INVALID_OFFSET = ((u64)1 << 50) - 1;
static const u32 HT_SPACE = 4096;
static u64 *MAGIC0 = (u64 *)"LSMT\0\1\2";
static const uuid_t MAGIC1 = UUID_INIT(0x657e63d2, 0x9444, 0x084c, 0xa2, 0xd2,
				       0xc8, 0xec, 0x4f, 0xcf, 0xae, 0x8a);

struct lsmt_ht {
	u64 magic0;
	uuid_t magic1;
	// offset 24, 28
	u32 size; //= sizeof(HeaderTrailer);
	u32 flags; //= 0;
	// offset 32, 40, 48
	u64 index_offset; // in bytes
	u64 index_size; // # of SegmentMappings
	u64 virtual_size; // in bytes
} __packed;

struct segment {
	u64 offset : 50;
	u32 length : 14;
};

struct segment_mapping { /* 8 + 8 bytes */
	u64 offset : 50; // offset (0.5 PB if in sector)
	u32 length : 14;
	u64 moffset : 55; // mapped offset (2^64 B if in sector)
	u32 zeroed : 1; // indicating a zero-filled segment
	u8 tag;
} __packed;

struct lsmt_ro_index {
	const struct segment_mapping *pbegin;
	const struct segment_mapping *pend;
	struct segment_mapping *mapping;
};

struct lsmt_ro_file {
	struct vfile_operations *ops;
	bool ownership;
	int nr;
	struct lsmt_ht ht;
	struct lsmt_ro_index *index;
	struct bio_set split_set;
	struct vfile *fp[0];
};

static size_t lsmt_len(struct vfile *fp);
static void lsmt_close(struct vfile *ctx);
static int lsmt_bioremap(struct vfile *ctx, struct bio *bio,
			 struct dm_dev **dev, unsigned int nr);

static struct vfile_operations lsmt_ops = { .len = lsmt_len,
					    .blkdev = NULL,
					    .pread = NULL,
					    .close = lsmt_close,
					    .bio_remap = lsmt_bioremap };

static u64 segment_end(const void *s)
{
	return ((struct segment *)s)->offset + ((struct segment *)s)->length;
}

static void forward_offset_to(void *m, u64 x, int8_t type)
{
	struct segment *s = (struct segment *)m;
	u64 delta = x - s->offset;

	s->offset = x;
	s->length -= delta;
	if (type == TYPE_SEGMENT_MAPPING) {
		struct segment_mapping *tmp = (struct segment_mapping *)m;

		if (!tmp->zeroed)
			tmp->moffset += delta;
	}
}

static void backward_end_to(void *m, u64 x)
{
	struct segment *s = (struct segment *)m;

	s->length = x - s->offset;
}

static void trim_edge(void *m, const struct segment *bound_segment, u8 type)
{
	if (((struct segment *)m)->offset < bound_segment->offset)
		forward_offset_to(m, bound_segment->offset, type);
	if (segment_end(m) > segment_end(bound_segment))
		backward_end_to(m, segment_end(bound_segment));
}

static const struct segment_mapping *
ro_index_lower_bound(const struct lsmt_ro_index *index, u64 offset)
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
	if (pret >= index->pend)
		return index->pend;
	else
		return pret;
}

static int ro_index_lookup(const struct lsmt_ro_index *index,
			   const struct segment *query_segment,
			   struct segment_mapping *ret_mappings, size_t n)
{
	const struct segment_mapping *lb;
	const struct segment_mapping *it;
	int cnt;

	if (query_segment->length == 0)
		return 0;
	lb = ro_index_lower_bound(index, query_segment->offset);
	cnt = 0;
	for (it = lb; it != index->pend; it++) {
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

static size_t ro_index_size(const struct lsmt_ro_index *index)
{
	return index->pend - index->pbegin;
}

static struct lsmt_ro_index *
create_memory_index(const struct segment_mapping *pmappings, size_t n,
		    u64 moffset_begin, u64 moffset_end)
{
	struct lsmt_ro_index *ret = NULL;

	ret = kmalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return NULL;
	ret->pbegin = pmappings;
	ret->pend = pmappings + n;
	ret->mapping = (struct segment_mapping *)pmappings;
	pr_info("create memory index done. {index_count: %zu}", n);
	return ret;
};

static int lsmt_bioremap(struct vfile *ctx, struct bio *bio,
			 struct dm_dev **dev, unsigned int nr)
{
	struct lsmt_ro_file *fp = (struct lsmt_ro_file *)ctx;
	struct segment s;
	struct segment_mapping m[16];
	struct bio *subbio;
	size_t i = 0;
	int n;
	loff_t offset = bio->bi_iter.bi_sector;

	if (bio_op(bio) != REQ_OP_READ) {
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}

	if ((offset << SECTOR_SHIFT) > fp->ht.virtual_size) {
		pr_info("LSMT: %lld over tail %lld\n", offset,
			fp->ht.virtual_size);
		pr_err("DM_MAPIO_KILL %s:%d op=%d sts=%d\n", __FILE__, __LINE__,
		       bio_op(bio), bio->bi_status);
		return DM_MAPIO_KILL;
	}

	// till here, take this bio, assume it will be submitted

	// actually, split bio by segment, summit and call endio when all split bio
	// are done

	bio->bi_status = BLK_STS_OK;
	while (true) {
		s.offset = bio->bi_iter.bi_sector;
		s.length = bio_sectors(bio);
		n = ro_index_lookup(fp->index, &s, m, 16);
		for (i = 0; i < n; ++i) {
			s.offset = bio->bi_iter.bi_sector;
			s.length = bio_sectors(bio);
			if (s.offset < m[i].offset) {
				// hole
				if (m[i].offset - s.offset < s.length) {
					subbio = bio_split(bio,
							   m[i].offset - s.offset,
							   GFP_NOIO, &fp->split_set);
					bio_chain(subbio, bio);
					zero_fill_bio(subbio);
					bio_endio(subbio);
				} else {
					zero_fill_bio(bio);
					bio_endio(bio);
					return DM_MAPIO_SUBMITTED;
				}
			}
			s.offset = bio->bi_iter.bi_sector;
			s.length = bio_sectors(bio);
			// zeroe block
			if (m[i].zeroed) {
				if (m[i].length < s.length) {
					subbio = bio_split(bio, m[i].length,
							   GFP_NOIO,
							   &fp->split_set);
					bio_chain(subbio, bio);
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
							   &fp->split_set);
					subbio->bi_iter.bi_sector =
						m[i].moffset;
					bio_chain(subbio, bio);
					submit_bio(subbio);
				} else {
					bio->bi_iter.bi_sector = m[i].moffset;
					submit_bio(bio);
					return DM_MAPIO_SUBMITTED;
				}
			}
		}
		if (n < 16)
			break;
	}
	if (s.length > 0)
		zero_fill_bio(bio);
	bio_endio(bio);
	return DM_MAPIO_SUBMITTED;
}

static size_t lsmt_len(struct vfile *fp)
{
	return ((struct lsmt_ro_file *)fp)->ht.virtual_size;
}

static bool is_lsmtfile(struct vfile *fp)
{
	struct lsmt_ht ht;
	ssize_t ret;

	if (!fp)
		return false;

	pr_info("LSMT: read header(vfile: %p)", fp);
	ret = fp->ops->pread(fp, &ht, sizeof(struct lsmt_ht), 0);

	if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
		pr_err("failed to load header");
		return NULL;
	}

	return ht.magic0 == *MAGIC0 && uuid_equal(&ht.magic1, &MAGIC1);
}

static void lsmt_close(struct vfile *ctx)
{
	struct lsmt_ro_file *lsmt_file = (struct lsmt_ro_file *)ctx;

	if (lsmt_file->ownership)
		for (int i = 0; i < lsmt_file->nr; i++)
			lsmt_file->fp[i]->ops->close(lsmt_file->fp[i]);
	vfree(lsmt_file->index->mapping);
	kfree(lsmt_file->index);
	bioset_exit(&lsmt_file->split_set);
	kfree(lsmt_file);
}

static void *lsmt_alloc_copy(void *ptr, size_t bs, size_t *from_size,
			     size_t to_size)
{
	void *ret = vmalloc(to_size * bs);

	if (IS_ERR_OR_NULL(ret))
		return ret;
	memcpy(ret, ptr, *from_size * bs);
	*from_size = to_size;
	vfree(ptr);
	return ret;
}

static int merge_indexes(int level, struct lsmt_ro_index **indexes, size_t n,
			 struct segment_mapping **mappings, size_t *size,
			 size_t *capacity, u64 start, u64 end)
{
	struct segment_mapping *p;
	struct segment_mapping it;
	const struct segment_mapping *pend;

	if (level >= n)
		return 0;
	p = (struct segment_mapping *)ro_index_lower_bound(indexes[level],
							   start);
	pend = indexes[level]->pend;
	if (p == pend) {
		pr_debug("index=%p p=%p pend=%p", indexes[level], p, pend);
		merge_indexes(level + 1, indexes, n, mappings, size, capacity,
			      start, end);
		return 0;
	}
	it = *p;
	if (start > it.offset)
		forward_offset_to(&it, start, TYPE_SEGMENT_MAPPING);
	while (p != pend) {
		if (end <= it.offset)
			break;
		if (start < it.offset)
			merge_indexes(level + 1, indexes, n, mappings, size,
				      capacity, start, it.offset);
		if (end < segment_end(&it))
			backward_end_to(&it, end);
		if (*size == *capacity) {
			*mappings = lsmt_alloc_copy(*mappings, sizeof(mappings),
						    capacity, (*capacity) << 1);
			if (*size == *capacity) {
				pr_err("realloc failed.");
				return -1;
			}
		}
		it.tag = level;
		(*mappings)[*size] = it;
		(*size)++;
		start = segment_end(p);
		pr_debug("push segment %zd {offset: %lu, len: %u}", *size,
			 it.offset + 0UL, it.length);
		p++;
		it = *p;
	}
	if (start < end)
		merge_indexes(level + 1, indexes, n, mappings, size, capacity,
			      start, end);
	return 0;
}

static struct lsmt_ro_index *
merge_memory_indexes(struct lsmt_ro_index **indexes, size_t n)
{
	size_t size = 0;
	size_t capacity = ro_index_size(indexes[0]);
	struct lsmt_ro_index *ret = NULL;
	struct segment_mapping *mappings;

	mappings = vmalloc(sizeof(*mappings) * capacity);

	pr_debug("init capacity: %zu\n", capacity);
	if (IS_ERR_OR_NULL(mappings)) {
		pr_err("Failed to alloc mapping memory\n");
		goto err_ret;
	}
	pr_debug("start merge indexes, layers: %zu", n);

	merge_indexes(0, indexes, n, &mappings, &size, &capacity, 0,
		      UINT64_MAX);
	pr_info("merge done, index size: %zu", size);
	ret = kmalloc(sizeof(*ret), GFP_KERNEL);
	mappings = lsmt_alloc_copy(mappings, sizeof(struct segment_mapping),
				   &size, size);
	ret->pbegin = mappings;
	ret->pend = mappings + size;
	ret->mapping = mappings;
	pr_info("ret index done. size: %zu", size);
	return ret;

err_ret:
	if (mappings)
		vfree(mappings);
	kfree(ret);
	return NULL;
}

static ssize_t do_load_index(struct vfile *fp, struct segment_mapping *p,
			     struct lsmt_ht *ht)
{
	ssize_t index_bytes = ht->index_size * sizeof(struct segment_mapping);
	ssize_t readn;
	size_t valid = 0;

	pr_info("LSMT: loadindex off: %llu cnt: %llu", ht->index_offset,
		ht->index_size);
	readn = fp->ops->pread(fp, p, index_bytes, ht->index_offset);
	if (readn < index_bytes) {
		pr_err("failed to read index");
		return -1;
	}
	for (off_t idx = 0; idx < ht->index_size; idx++) {
		if (p[idx].offset != INVALID_OFFSET) {
			p[valid] = p[idx];
			p[valid].tag = 0;
			pr_debug("valid index %zu {offset: %lu, length: %u}",
				 valid, p[idx].offset + 0UL, p[idx].length);
			valid++;
		}
	}
	pr_info("valid index count: %zu", valid);
	ht->index_size = valid;
	return valid;
}

static ssize_t lsmt_load_ht(struct vfile *fp, struct lsmt_ht *ht)
{
	ssize_t file_size;
	loff_t tailer_offset;
	ssize_t ret;

	if (!is_lsmtfile(fp)) {
		pr_info("LSMT: fp is not a lsmtfile(%p)\n", fp);
		return -1;
	}
	file_size = fp->ops->len(fp);
	pr_info("LSMT: file len is %zd\n", file_size);
	tailer_offset = file_size - HT_SPACE;
	ret = fp->ops->pread(fp, ht, sizeof(struct lsmt_ht), tailer_offset);
	if (ret < (ssize_t)sizeof(struct lsmt_ht)) {
		pr_err("failed to load tailer(%p)\n", fp);
		return -1;
	}
	pr_info("LSMT(%p), index_offset %llu: index_count: %llu", fp,
		ht->index_offset, ht->index_size);

	return 0;
}

static struct lsmt_ro_index *load_merge_index(struct vfile *files[], size_t n,
					      struct lsmt_ht *ht)
{
	struct lsmt_ro_index **indexes;
	struct lsmt_ro_index *pmi = NULL;
	struct segment_mapping *p;
	struct lsmt_ro_index *pi;
	size_t index_bytes;

	indexes = kzalloc(sizeof(**indexes) * OVBD_MAX_LAYERS, GFP_KERNEL);
	if (n > OVBD_MAX_LAYERS) {
		pr_err("too many indexes to merge, %d at most!",
		       OVBD_MAX_LAYERS);
		goto error_ret;
	}
	for (int i = 0; i < n; ++i) {
		pr_info("read %d-th LSMT info", i);
		lsmt_load_ht(files[i], ht);
		index_bytes = ht->index_size * sizeof(struct segment_mapping);
		if (index_bytes == 0 || index_bytes > 1024UL * 1024 * 1024)
			goto error_ret;
		p = vmalloc(index_bytes);
		if (do_load_index(files[i], p, ht) == -1) {
			vfree(p);
			pr_err("failed to load index from %d-th file", i);
			goto error_ret;
		}
		pi = create_memory_index(p, ht->index_size,
					 HT_SPACE / ALIGNMENT,
					 ht->index_offset / ALIGNMENT);
		if (!pi) {
			pr_err("failed to create memory index! ( %d-th file )",
			       i);
			vfree(p);
			goto error_ret;
		}
		indexes[i] = pi;
	}

	pr_info("reverse index.");
	REVERSE_ARRAY(struct vfile *, &files[0], &files[n - 1]);
	REVERSE_ARRAY(struct lsmt_ro_index *, &indexes[0], &indexes[n - 1]);

	pmi = merge_memory_indexes(indexes, n);

	if (!pmi) {
		pr_err("failed to merge indexes");
		goto error_ret;
	}
	pr_debug("merge index done.");
	kfree(indexes);
	return pmi;

error_ret:
	kfree(indexes);
	return NULL;
}

struct vfile *lsmt_open_files(struct vfile *zfiles[], int n)
{
	struct lsmt_ro_file *ret;
	struct lsmt_ht ht;
	struct lsmt_ro_index *idx;

	pr_info("LSMT open_files, layers: %d", n);
	ret = kzalloc(sizeof(struct vfile *) * n + sizeof(struct lsmt_ro_file),
		      GFP_KERNEL);
	if (!ret)
		return NULL;
	idx = load_merge_index(zfiles, n, &ht);
	if (!idx) {
		pr_err("load merge index failed.");
		goto error_out;
	}
	pr_info("Initial bio set");
	if (bioset_init(&ret->split_set, BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS)) {
		pr_err("Initial bio set failed");
		goto error_out;
	}
	ret->nr = n;
	ret->index = idx;
	ret->ownership = false;
	ret->ops = &lsmt_ops;
	ret->ht.virtual_size = ht.virtual_size;
	pr_debug("ret->fp[0]: %p", &ret->fp[0]);
	memcpy(&ret->fp[0], &zfiles[0], n * sizeof(struct vfile *));
	return (struct vfile *)ret;
error_out:
	kfree(ret);
	return NULL;
}
