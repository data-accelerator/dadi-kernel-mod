#ifndef __DM_OVBD_HEADER__
#define __DM_OVBD_HEADER__

#include <linux/device-mapper.h>
#include <linux/bio.h>

typedef struct ovbd_context {
	struct workqueue_struct *wq;
} ovbd_context;

ovbd_context *get_ovbd_context(void);

int init_lsmt_target(void);

void cleanup_lsmt_target(void);

int init_zfile_target(void);

void cleanup_zfile_target(void);

struct vfile;

typedef struct vfile_operations {
	struct block_device *(*blkdev)(struct vfile *);
	size_t (*len)(struct vfile *);
	ssize_t (*pread)(struct vfile *, void *, size_t, loff_t);
	int (*bio_remap)(struct vfile *, struct bio *, struct dm_dev **,
			 unsigned int);
	void (*close)(struct vfile *);
} vfile_operations;

typedef struct vfile {
	vfile_operations *ops;
} vfile;

vfile *open_blkdev_as_vfile(struct block_device *blk, loff_t len);

vfile *zfile_open(struct vfile *file);

vfile *lsmt_open_files(vfile *zf[], int n);

#endif