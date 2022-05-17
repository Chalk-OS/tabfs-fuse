#ifndef __TABFS_FUSE_OPTIONS_H__
#define __TABFS_FUSE_OPTIONS_H__

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <libtabfs/libtabfs.h>
#include <stddef.h>

struct tabfs_fuse_options {
    char* devFile;
    int header_offset;
    int header_offset_is_abs;
    int readonly;
};

extern libtabfs_volume_t* gVolume;

#define OPTION(t, p) {t, offsetof(struct tabfs_fuse_options, p), 1}
static const struct fuse_opt option_spec[] = {
    OPTION("--dev=%s", devFile),
    OPTION("--headeroffset=%d", header_offset),
    OPTION("--headeroffset_abs", header_offset_is_abs),
    OPTION("--readonly", readonly),
    FUSE_OPT_END
};

extern struct tabfs_fuse_options options;

#endif //__TABFS_FUSE_OPTIONS_H__