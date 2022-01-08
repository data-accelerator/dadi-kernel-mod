#ifndef __BLKFILE_RO__
#define __BLKFILE_RO__

#include "vfile.h"

struct blkdev_as_vfile {
	IFile vfile;
	loff_t len;
	struct block_device *dev;
};

IFile *open_blkdev_as_vfile(struct block_device *blk, loff_t len);

#endif