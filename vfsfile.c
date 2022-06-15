#include "vfsfile.h"
#include "log-format.h"

#include <linux/fadvise.h>

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
			PRINT_INFO(
				"zfile: read underlay file at %lld, pos move to %lld, return "
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

size_t ffile_len(IFile *ctx)
{
	struct vfs_vfile *fp = (struct vfs_vfile *)ctx;
	return file_len(fp->file);
}

ssize_t ffile_pread(IFile *ctx, void *buf, size_t count, loff_t offset)
{
	struct vfs_vfile *fp = (struct vfs_vfile *)ctx;
	return file_read(fp->file, buf, count, offset);
}

void ffile_close(IFile *ctx)
{
	struct vfs_vfile *fp = (struct vfs_vfile *)ctx;
	file_close(fp->file);
}

static struct vfile_op ffile_ops = { .len = ffile_len,
				     .pread = ffile_pread,
				     .close = ffile_close };

IFile *open_file_as_vfile(struct file *file)
{
	struct vfs_vfile *ret = NULL;
	if (!file)
		return NULL;
	ret = kmalloc(sizeof(struct vfs_vfile), GFP_KERNEL);
	ret->file = file;
	ret->vfile.op = &ffile_ops;
	return (IFile *)ret;
}

IFile *open_path_as_vfile(const char *fn, int flags, mode_t mode)
{
	struct file *fp = NULL;
	if (!fn)
		return NULL;
	fp = file_open(fn, flags, mode);
	if (!fp)
		goto fail;
	return open_file_as_vfile(fp);
fail:
	file_close(fp);
	return NULL;
}
