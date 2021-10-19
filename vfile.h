#ifndef __VFILE_H__
#define __VFILE_H__

#include <linux/types.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
typedef int (*ovbd_cb_fn)(int err, void *context);

struct vfile;
typedef size_t (*file_len_fn)(struct vfile *ctx);
typedef ssize_t (*pread_fn)(struct vfile *ctx, void *buf, size_t count,
			    loff_t offset);
typedef ssize_t (*pread_async_fn)(struct vfile *ctx, void *buf, size_t count,
				  loff_t offset);
typedef int (*bio_remap_fn)(struct vfile *ctx, struct bio *bio,
			    struct dm_dev **dm_dev, unsigned int nr);
typedef void (*close_fn)(struct vfile *ctx);

struct vfile_op {
	file_len_fn len;
	pread_fn pread;
	pread_async_fn pread_async;
	bio_remap_fn bio_remap;
	close_fn close;
};

struct vfile {
	struct vfile_op *op;
};

#endif