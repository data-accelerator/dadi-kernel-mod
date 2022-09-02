#ifndef __BLKFILE_RO__
#define __BLKFILE_RO__

#include "vfile.h"

struct blkdev_as_vfile {
	IFile vfile;
	loff_t len;
	struct dm_bufio_client *c;

};

IFile *open_blkdev_as_vfile(struct block_device *blk, loff_t len);

#endif