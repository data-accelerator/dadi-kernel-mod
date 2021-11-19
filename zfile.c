#include "zfile.h"

#include <linux/buffer_head.h>
#include <linux/errno.h>
#include <linux/fadvise.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/lz4.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
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

static struct file *file_open(const char *path, int flags, int rights)
{
	struct file *fp = NULL;
	fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		PRINT_ERROR("Cannot open the file %ld", PTR_ERR(fp));
		return NULL;
	}
	vfs_fadvise(fp, 0, fp->f_inode->i_size, POSIX_FADV_RANDOM);
	PRINT_INFO("Opened the file %s", path);
	return fp;
}

static void file_close(struct file *file)
{
	filp_close(file, NULL);
}

static size_t file_len(struct file *file)
{
	return file ? file->f_inode->i_size : 0;
}

static ssize_t file_read(struct file *file, void *buf, size_t count, loff_t pos)
{
	ssize_t ret, sret = 0;
	loff_t lpos;
	size_t flen = file_len(file);
	if (pos > flen)
		return 0;
	if (pos + count > flen)
		count = flen - pos;
	vfs_fadvise(file, pos, count, POSIX_FADV_SEQUENTIAL);
	while (count > 0) {
		lpos = pos;
		ret = kernel_read(file, buf, count, &lpos);
		if (lpos <= pos || ret <= 0) {
			PRINT_INFO("zfile: read underlay file at %lld, pos move to %lld, return "
				"%ld\n",
				pos, lpos, ret);
			return ret;
		}
		count -= (lpos - pos);
		buf += (lpos - pos);
		sret += (lpos - pos);
		pos = lpos;
	}
	return sret;
}

size_t zfile_len(struct vfile *zfile)
{
	return ((struct zfile *)zfile)->header.vsize;
}

struct path zfile_getpath(struct zfile *zfile)
{
	return zfile->fp->f_path;
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
	unsigned char *src_buf;
	unsigned char *decomp_buf;
	loff_t decomp_offset;
	unsigned char *c_buf;
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

	src_buf = kmalloc(range, GFP_NOIO);
	decomp_buf = kmalloc(zf->header.opt.block_size, GFP_NOIO);

	// read compressed data
	ret = file_read(zf->fp, src_buf, range, begin);
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

	// invalid caches
	invalidate_mapping_pages(zf->fp->f_mapping, begin >> PAGE_SHIFT,
				 ((begin + range) >> PAGE_SHIFT) - 1);

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
	PRINT_INFO("close(%lx)", f);
	if (zfile) {
		if (zfile->jump) {
			vfree(zfile->jump);
			zfile->jump = NULL;
		}
		if (zfile->fp) {
			file_close(zfile->fp);
			zfile->fp = NULL;
		}
		kfree(zfile);
	}
}

static struct vfile_op zfile_ops = { .len = zfile_len,
				     .pread = zfile_read,
				     .pread_async = NULL,
				     .close = zfile_close };

struct zfile *zfile_open_by_file(struct file *file)
{
	uint32_t *jt_saved;
	size_t jt_size = 0;
	struct zfile *zfile = NULL;
	int ret = 0;
	size_t file_size = 0;
	loff_t tailer_offset;
	zfile = kzalloc(sizeof(struct zfile), GFP_KERNEL);

	if (!is_zfile(file, &zfile->header)) {
		return NULL;
	}

	if (!zfile) {
		goto error_out;
	}
	zfile->fp = file;

	// should verify header
	if (!is_header_overwrite(&zfile->header)) {
		file_size = file_len(zfile->fp);
		tailer_offset = file_size - ZF_SPACE;
		PRINT_INFO("zfile: file_size=%lu", file_size);
		ret = file_read(zfile->fp, &zfile->header,
				sizeof(struct zfile_ht), tailer_offset);
		PRINT_INFO("zfile: Trailer vsize=%lld index_offset=%lld index_size=%lld "
			"verify=%d",
			zfile->header.vsize, zfile->header.index_offset,
			zfile->header.index_size, zfile->header.opt.verify);
	} else {
		PRINT_INFO("zfile header overwrite: size=%lld index_offset=%lld "
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

	ret = file_read(zfile->fp, jt_saved, jt_size,
			zfile->header.index_offset);

	build_jump_table(jt_saved, zfile);

	vfree(jt_saved);

	zfile->vfile.op = &zfile_ops;

	return zfile;

error_out:
	if (zfile)
		zfile_close((struct vfile *)zfile);
	return NULL;
}

struct zfile *zfile_open(const char *path)
{
	struct zfile *ret = NULL;
	struct file *file = file_open(path, 0, 644);
	if (!file) {
		PRINT_ERROR("zfile: Canot open zfile %s", path);
		return NULL;
	}
	ret = zfile_open_by_file(file);
	if (!ret) {
		file_close(file);
	}
	return ret;
}

struct file *zfile_getfile(struct zfile *zfile)
{
	return zfile->fp;
}

bool is_zfile(struct file *file, struct zfile_ht *ht)
{
	ssize_t ret;
	if (!file)
		return false;

	ret = file_read(file, ht, sizeof(struct zfile_ht), 0);
	if (ret < (ssize_t)sizeof(struct zfile_ht)) {
		PRINT_INFO("zfile: failed to load header %ld", ret);
		return false;
	}
	return ht->magic0 == *MAGIC0 && uuid_equal(&(ht->magic1), &MAGIC1);
}
