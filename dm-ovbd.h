/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __DM_OVBD_HEADER__
#define __DM_OVBD_HEADER__

#include <linux/device-mapper.h>
#include <linux/bio.h>

struct ovbd_context {
	struct workqueue_struct *wq;
};

struct ovbd_context *get_ovbd_context(void);

int init_lsmt_target(void);

void cleanup_lsmt_target(void);

int init_zfile_target(void);

void cleanup_zfile_target(void);

struct vfile;

struct vfile_operations {
	struct block_device *(*blkdev)(struct vfile *file);
	size_t (*len)(struct vfile *file);
	ssize_t (*pread)(struct vfile *file, void *buffer, size_t count,
			 loff_t offset);
	int (*bio_remap)(struct vfile *file, struct bio *bio,
			 struct dm_dev **devs, unsigned int nr_dev);
	void (*close)(struct vfile *file);
};

struct vfile {
	struct vfile_operations *ops;
};

struct vfile *open_blkdev_as_vfile(struct block_device *blk, loff_t len);

struct vfile *zfile_open(struct vfile *file);

struct vfile *lsmt_open_files(struct vfile *zf[], int n);

#endif
