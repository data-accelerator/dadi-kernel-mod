#ifndef __VFSFILE_RO__
#define __VFSFILE_RO__

#include <linux/fs.h>

#include "vfile.h"

struct vfs_vfile {
	IFile vfile;
    struct file *file;
};

IFile *open_file_as_vfile(struct file *file);
IFile *open_path_as_vfile(const char* fn, int flags, mode_t mode);

#endif