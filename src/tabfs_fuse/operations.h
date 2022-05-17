#ifndef __TABFS_FUSE_OPERATIONS_H__
#define __TABFS_FUSE_OPERATIONS_H__

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

extern const struct fuse_operations tabfs_oper;

#endif //__TABFS_FUSE_OPERATIONS_H__