#include "operations.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// include <stddef.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <unistd.h>

#include "options.h"

#include <libtabfs/libtabfs.h>

//--------------------------------------------------------------------------------
// Init & Destory of filesystem
//--------------------------------------------------------------------------------

static void* tabfs_init(struct fuse_conn_info* conn, struct fuse_config* conf) {
    conf->debug = 1;
    return gVolume;
}

void tabfs_destroy(void* private_data) {
    libtabfs_volume_t* volume = (libtabfs_volume_t*) private_data;
    libtabfs_destroy_volume(volume);
}

//--------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------

#define obtain_tabfs_entry(v, p, e)     { int r = obtain_tabfs_entry_real(v, p, e, NULL, NULL); if (r != 0) { return r; } }
#define obtain_tabfs_entry_ex(v, p, e, et, o)     { int r = obtain_tabfs_entry_real(v, p, e, et, o); if (r != 0) { return r; } }

static int obtain_tabfs_entry_real(
    libtabfs_volume_t* volume, const char* path, libtabfs_entrytable_entry_t** entry_out,
    libtabfs_entrytable_t** entrytable_out, int* offset_out
) {
    char* path_buff = strdup(path);

    unsigned int uid = fuse_get_context()->uid;
    unsigned int gid = fuse_get_context()->gid;

    libtabfs_error err = libtabfs_entrytab_traversetree(
        volume->__root_table, path_buff + 1, false, uid, gid, entry_out, entrytable_out, offset_out
    );

    free(path_buff);
    if (err == LIBTABFS_ERR_NOT_FOUND) { return -ENOENT; }
    if (err != LIBTABFS_ERR_NONE) {
        printf("[obtain_tabfs_entry_real] got error while traversing tree (%s): %s (%d)\n", path, libtabfs_errstr(err), err);
        switch (err) {
            case LIBTABFS_ERR_IS_NO_DIR:    return -ENOTDIR;
            case LIBTABFS_ERR_NO_PERM:      return -EACCES;
            case LIBTABFS_ERR_NAME_TOLONG:  return -ENAMETOOLONG;
            default:                        return -EPERM;
        }
    }
    if (*entry_out == NULL) { return -ENOENT; }
    return 0;
}

static libtabfs_fileflags_t fileflags_from_mode(mode_t mode) {
    return (libtabfs_fileflags_t) {
        .user = {
            .read  = (mode & S_IRUSR) != 0,
            .write = (mode & S_IWUSR) != 0,
            .exec  = (mode & S_IXUSR) != 0,
        },
        .group = {
            .read  = (mode & S_IRGRP) != 0,
            .write = (mode & S_IWGRP) != 0,
            .exec  = (mode & S_IXGRP) != 0,
        },
        .other = {
            .read  = (mode & S_IROTH) != 0,
            .write = (mode & S_IWOTH) != 0,
            .exec  = (mode & S_IXOTH) != 0,
        },
        .set_uid = (mode & S_ISUID) != 0,
        .set_gid = (mode & S_ISGID) != 0,
        .sticky = (mode & __S_ISVTX) != 0,
    };
}

static mode_t mode_from_entry(libtabfs_entrytable_entry_t* entry) {
    mode_t mode = 0;
    mode |= entry->flags.sticky ? __S_ISVTX : 0;
    mode |= entry->flags.set_gid ? S_ISGID : 0;
    mode |= entry->flags.set_uid ? S_ISUID : 0;

    mode |= LIBTABFS_TAB_ENTRY_ACLUSR(entry) << 6;
    mode |= LIBTABFS_TAB_ENTRY_ACLGRP(entry) << 3;
    mode |= LIBTABFS_TAB_ENTRY_ACLOTH(entry);
    return mode;
}

//--------------------------------------------------------------------------------
// Common operations
//--------------------------------------------------------------------------------

static int tabfs_getattr(const char* path, struct stat* st, struct fuse_file_info *fi) {
    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;

    if (strcmp(path, "/") == 0) {
        // accessing root directory directly!
        st->st_mode = __S_IFDIR | 0755;
        st->st_nlink = 2;
        st->st_size = 4096;     // TODO: change this into the size of our entrytable in bytes

        // root dir is owned by the user that mounted the fs
        st->st_uid = getuid();
        st->st_gid = getgid();
        return 0;
    }
    else {
        // path is always absolute (it seems)

        libtabfs_entrytable_entry_t* entry = NULL;
        obtain_tabfs_entry(volume, path, &entry);

        st->st_mode = 0;
        switch (entry->flags.type) {
            case LIBTABFS_ENTRYTYPE_DIR: {
                st->st_mode |= __S_IFDIR;
                st->st_nlink = 2;
                st->st_size = entry->data.dir.size;
                break;
            }
            case LIBTABFS_ENTRYTYPE_FILE_FAT: {
                st->st_mode |= __S_IFREG;
                st->st_size = 12;
                break;
            }
            case LIBTABFS_ENTRYTYPE_FILE_SEG        :   return -EPERM;
            case LIBTABFS_ENTRYTYPE_DEV_CHR         :   st->st_mode |= __S_IFCHR; break;
            case LIBTABFS_ENTRYTYPE_DEV_BLK         :   st->st_mode |= __S_IFBLK; break;
            case LIBTABFS_ENTRYTYPE_FIFO            :   st->st_mode |= __S_IFIFO; break;
            case LIBTABFS_ENTRYTYPE_SYMLINK         :   st->st_mode |= __S_IFLNK; break;
            case LIBTABFS_ENTRYTYPE_SOCKET          :   st->st_mode |= __S_IFSOCK; break;
            case LIBTABFS_ENTRYTYPE_FILE_CONTINUOUS :   st->st_mode |= __S_IFREG; break;
            case LIBTABFS_ENTRYTYPE_LONGNAME        :   return -EPERM;
            case LIBTABFS_ENTRYTYPE_TABLEINFO       :   return -EPERM;
            case LIBTABFS_ENTRYTYPE_KERNEL          :   st->st_mode |= __S_IFREG; break;
            default: return -EPERM;
        }
        st->st_mode |= mode_from_entry(entry);

        st->st_uid = entry->user_id;
        st->st_gid = entry->group_id;

        st->st_ctime = entry->create_ts.i64_data;
        st->st_mtime = entry->modify_ts.i64_data;
        st->st_atime = entry->access_ts.i64_data;
    }
    return 0;
}

static int tabfs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
    if (strcmp(path, "/") == 0) {
        return -EPERM;
    }

    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;
    libtabfs_entrytable_entry_t* entry = NULL;
    obtain_tabfs_entry(volume, path, &entry);
    libtabfs_fileflags_to_entry( fileflags_from_mode(mode), entry);
    return 0;
}

int tabfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* fi) {
    if (strcmp(path, "/") == 0) {
        return -EPERM;
    }

    // TODO: validate if we need to check if we have the permission to change owner
    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;
    libtabfs_entrytable_entry_t* entry = NULL;
    obtain_tabfs_entry(volume, path, &entry);
    libtabfs_entry_chown(entry, uid, gid);
    return 0;
}

int tabfs_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info* fi) {
    // https://man7.org/linux/man-pages/man2/utimensat.2.html

    if (strcmp(path, "/") == 0) {
        return -EPERM;
    }

    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;
    libtabfs_entrytable_entry_t* entry = NULL;
    obtain_tabfs_entry(volume, path, &entry);

    libtabfs_time_t atime = { .i64_data = tv[0].tv_sec };
    libtabfs_time_t mtime = { .i64_data = tv[1].tv_sec };

    libtabfs_entry_touch(entry, mtime, atime);
    return 0;
}

// https://man7.org/linux/man-pages/man2/access.2.html
int tabfs_access(const char* path, int mode) {
    if (mode == F_OK) {
        // check if file exists
        if (strcmp(path, "/") == 0) {
            return 0;   // root always exist
        }

        libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;
        libtabfs_entrytable_entry_t* entry = NULL;
        obtain_tabfs_entry(volume, path, &entry);
        return 0;
    }
    else {
        if (strcmp(path, "/") == 0) {
            // root dir is currently hardcoded to 0755!

            if ((mode & R_OK) != 0 || (mode & X_OK) != 0) {
                return 0;
            }

            return -EPERM;
        }

        libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;
        libtabfs_entrytable_entry_t* entry = NULL;
        obtain_tabfs_entry(volume, path, &entry);

        unsigned char perm = 0;
        if ((mode & R_OK) != 0) { perm |= 0b100; }
        if ((mode & W_OK) != 0) { perm |= 0b010; }
        if ((mode & X_OK) != 0) { perm |= 0b001; }

        unsigned int uid = fuse_get_context()->uid;
        unsigned int gid = fuse_get_context()->gid;
        if ( libtabfs_check_perm(entry, uid, gid, perm) ) {
            return 0;
        }
        return -EPERM;
    }
}

//--------------------------------------------------------------------------------
// IOCTL
//--------------------------------------------------------------------------------

const char* ioctl_cmd_tostr(int cmd) {
    switch (cmd) {
        case FS_IOC_GETFLAGS:   return "FS_IOC_GETFLAGS";
        case FS_IOC_SETFLAGS:   return "FS_IOC_SETFLAGS";
        case FS_IOC_GETVERSION: return "FS_IOC_GETVERSION";
        case FS_IOC_SETVERSION: return "FS_IOC_SETVERSION";
        // case FS_IOC_FIEMAP:     return "FS_IOC_FIEMAP";
        case FS_IOC32_GETFLAGS: return "FS_IOC32_GETFLAGS";
        case FS_IOC32_SETFLAGS: return "FS_IOC32_SETFLAGS";
        case FS_IOC32_GETVERSION: return "FS_IOC32_GETVERSION";
        case FS_IOC32_SETVERSION: return "FS_IOC32_SETVERSION";
        case FS_IOC_FSGETXATTR: return "FS_IOC_FSGETXATTR";
        case FS_IOC_FSSETXATTR: return "FS_IOC_FSSETXATTR";
        case FS_IOC_GETFSLABEL: return "FS_IOC_GETFSLABEL";
        case FS_IOC_SETFSLABEL: return "FS_IOC_SETFSLABEL";

        default:
            return "???";
    }
}

int tabfs_ioctl(const char* path, int cmd, void* arg, struct fuse_file_info* fi, unsigned int flags, void* data) {
    // if (strcmp(path, "/") == 0) {
    //     return -EINVAL;
    // }

    if (flags & FUSE_IOCTL_COMPAT) {
        return -ENOSYS;
    }

    printf(
        "[ioctl] path: %s | cmd: %s (0x%X) | arg: %p | flags: 0x%X | data: %p\n",
        path, ioctl_cmd_tostr(cmd), cmd, arg, flags, data
    );

    switch (cmd) {
        // implement getflags & setflags even if not currently used; lsattr seemingly ignores failures of the ioctl commands
        case FS_IOC_GETFLAGS:
            *(int*)data = 0;
            return -ENOSYS;

        case FS_IOC_SETFLAGS:
            return -ENOSYS;

        default:
            break;
    }

    return -EPERM;
}


int tabfs_listxattr(const char* path, char* list, size_t size) {
    return -ENOSYS;
}

//--------------------------------------------------------------------------------
// Directory operations
//--------------------------------------------------------------------------------

int tabfs_readdir(
    const char* path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi, enum fuse_readdir_flags flags
) {
    // TODO: implement usage of offset

    filler(buffer, ".", NULL, 0, 0);
    filler(buffer, "..", NULL, 0, 0);

    // iterate over the complete entrytable and fill in any file found!
    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;

    libtabfs_entrytable_t* tab = NULL;
    if (strcmp(path, "/") == 0) {
        tab = volume->__root_table;
    }
    else {
        libtabfs_entrytable_entry_t* entry = NULL;
        obtain_tabfs_entry(volume, path, &entry);

        if (entry->flags.type != LIBTABFS_ENTRYTYPE_DIR) { return -ENOTDIR; }
        tab = libtabfs_get_entrytable(volume, entry->data.dir.lba, entry->data.dir.size);
    }

    int entryCount = tab->__byteSize / 64;
    for (int i = 1; i < entryCount; i++) {
        libtabfs_entrytable_entry_t* dirent = &( tab->entries[i] );

        if (dirent->flags.type == LIBTABFS_ENTRYTYPE_UNKNOWN) {
            continue;
        }

        char* name = NULL;
        if (dirent->longname_data.longname_identifier == 0x00) {
            name = dirent->name;
        }
        else {
            libtabfs_entrytable_t* tab = libtabfs_get_entrytable(volume, dirent->longname_data.longname_lba, dirent->longname_data.longname_lba_size);
            libtabfs_entrytable_longname_t* lne = &( tab->entries[dirent->longname_data.longname_offset] );
            name = lne->name;
        }

        filler(buffer, name, NULL, 0, 0);
    }

    return 0;
}

int tabfs_mkdir(const char* path, mode_t mode) {
    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;

    char* path_buff = strdup(path);
    char* last_delim = strrchr(path_buff, '/');

    unsigned int uid = fuse_get_context()->uid;
    unsigned int gid = fuse_get_context()->gid;

    libtabfs_entrytable_t* tab = NULL;
    if (last_delim != path_buff) {
        *last_delim = '\0';

        libtabfs_entrytable_entry_t* entry = NULL;
        libtabfs_error err = libtabfs_entrytab_traversetree(
            volume->__root_table, path_buff + 1, false, uid, gid, &entry, NULL, NULL
        );
        if (err == LIBTABFS_ERR_NOT_FOUND) { return -ENOENT; }
        if (err != LIBTABFS_ERR_NONE) {
            printf("[tabfs_mkdir] got error while traversing tree (%s): %s (%d)\n", path, libtabfs_errstr(err), err);
            free(path_buff);
            switch (err) {
                case LIBTABFS_ERR_IS_NO_DIR:    return -ENOTDIR;
                case LIBTABFS_ERR_NO_PERM:      return -EACCES;
                case LIBTABFS_ERR_NAME_TOLONG:  return -ENAMETOOLONG;
                default:                        return -EPERM;
            }
        }
        if (entry == NULL) { return -ENOENT; }
        if (entry->flags.type != LIBTABFS_ENTRYTYPE_DIR) { return -ENOTDIR; }
        tab = libtabfs_get_entrytable(volume, entry->data.dir.lba, entry->data.dir.size);
    }
    else {
        tab = volume->__root_table;
    }

    libtabfs_entrytable_t* dirtab;

    libtabfs_time_t c_time;
    c_time.i64_data = time(NULL);

    libtabfs_error err = libtabfs_create_dir(tab, last_delim + 1, fileflags_from_mode(mode), c_time, uid, gid, &dirtab);
    if (err != LIBTABFS_ERR_NONE) {
        return -EPERM;
    }
    return 0;
}

int tabfs_rmdir(const char* path) {
    if (strcmp(path, "/") == 0) {
        return -EPERM;
    }

    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;

    libtabfs_entrytable_entry_t* entry = NULL;
    libtabfs_entrytable_t* entrytable = NULL;
    int offset;
    obtain_tabfs_entry_ex(volume, path, &entry, &entrytable, &offset);
    if (entry->flags.type != LIBTABFS_ENTRYTYPE_DIR) { return -ENOTDIR; }

    libtabfs_entrytable_t* dirtab = libtabfs_get_entrytable(volume, entry->data.dir.lba, entry->data.dir.size);
    int count = libtabfs_entrytable_count_entries(dirtab, true);
    if (count > 0) {
        return -ENOTEMPTY;
    }

    // first remove the entry
    entrytable->entries[offset].flags.type = LIBTABFS_ENTRYTYPE_UNKNOWN;

    // then delete the entrytable itself
    while (dirtab != NULL) {
        libtabfs_entrytable_t* tmp = dirtab;
        dirtab = libtabfs_entrytable_nextsection(tmp);
        libtabfs_entrytable_remove(tmp);
    }

    return 0;
}

int tabfs_fsyncdir(const char* path, int i, struct fuse_file_info* fi) {
    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;
    libtabfs_entrytable_t* tab = NULL;
    if (strcmp(path, "/") == 0) {
        tab = volume->__root_table;
    }
    else {
        libtabfs_entrytable_entry_t* dirent = NULL;
        obtain_tabfs_entry(volume, path, &dirent);
        if (dirent->flags.type != LIBTABFS_ENTRYTYPE_DIR) { return -ENOTDIR; }
        tab = libtabfs_get_entrytable(volume, dirent->data.dir.lba, dirent->data.dir.size);
    }

    while (tab != NULL) {
        libtabfs_entrytable_sync(tab);
        tab = libtabfs_entrytable_nextsection(tab);
    }
    return 0;
}

int tabfs_opendir(const char* path, struct fuse_file_info* fi) {
    fi->cache_readdir = 0;  // do not cache readdir for now

    // TODO: implement opendir correctly

    return 0;
}

int tabfs_releasedir(const char* path, struct fuse_file_info* fi) {
    //printf("releasedir: path=%s | fi.flush=%d\n", path, fi->flush);
    return 0;
}

//--------------------------------------------------------------------------------
// Misc.
//--------------------------------------------------------------------------------

int tabfs_mknod(const char* path, mode_t mode, dev_t dev) {
    printf("mknod: path=%s | mode=%o | dev=0x%X\n", path, mode, dev);

    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;

    char* path_buff = strdup(path);
    char* last_delim = strrchr(path_buff, '/');

    libtabfs_entrytable_t* tab = NULL;

    unsigned int uid = fuse_get_context()->uid;
    unsigned int gid = fuse_get_context()->gid;

    if (last_delim != path_buff) {
        *last_delim = '\0';

        libtabfs_entrytable_entry_t* entry = NULL;
        libtabfs_error err = libtabfs_entrytab_traversetree(
            volume->__root_table, path_buff + 1, false, uid, gid, &entry, NULL, NULL
        );

        if (err != LIBTABFS_ERR_NONE) {
            printf("got error while traversing tree (%s): %s (%d)\n", path, libtabfs_errstr(err), err);
            free(path_buff);
            switch (err) {
                case LIBTABFS_ERR_IS_NO_DIR:    return -ENOTDIR;
                case LIBTABFS_ERR_NO_PERM:      return -EACCES;
                case LIBTABFS_ERR_NAME_TOLONG:  return -ENAMETOOLONG;
                case LIBTABFS_ERR_NOT_FOUND:    return -ENOENT;
                default:                        return -EPERM;
            }
        }

        if (entry == NULL) { return -ENOENT; }
        if (entry->flags.type != LIBTABFS_ENTRYTYPE_DIR) { return -ENOTDIR; }

        tab = libtabfs_get_entrytable(volume, entry->data.dir.lba, entry->data.dir.size);
    }
    else {
        tab = volume->__root_table;
    }

    libtabfs_fileflags_t fileflags = fileflags_from_mode(mode);
    char* name = last_delim + 1;

    libtabfs_time_t c_time;
    c_time.i64_data = time(NULL);

    libtabfs_error err;
    if (S_ISCHR(mode)) {
        err = libtabfs_create_chardevice(tab, name, fileflags, c_time, uid, gid, dev, 0x0);
    }
    else if (S_ISBLK(mode)) {
        err = libtabfs_create_blockdevice(tab, name, fileflags, c_time, uid, gid, dev, 0x0);
    }
    else if (S_ISREG(mode)) {
        // regular files are fat files for now...
        libtabfs_entrytable_entry_t* entry = NULL;
        err = libtabfs_create_fatfile(tab, name, fileflags, c_time, uid, gid, &entry);
    }
    // else if (S_ISFIFO(mode)) {
    //     err = libtabfs_create_fifo(tab, name, fileflags, c_time, uid, gid, dev, 0x0);
    // }
    // else if (S_ISSOCK(mode)) {
    //     
    // }
    else {
        printf("[tabfs_mknod] Unknown file mode to create: %o\n", mode);
        return -EPERM;
    }

    if (err != LIBTABFS_ERR_NONE) {
        return -EPERM;
    }
    return 0;
};

int tabfs_flush(const char* path, struct fuse_file_info* fi) {
    printf("flush: %s\n", path);
    // TODO: implement flush
    return 0;
}

void tabfs_rename (const char* path, const char* newpath, unsigned int flags) {
    printf("rename: path=%s newpath=%s flags=%d\n", path, newpath, flags);
    // TODO: implement rename
}

int tabfs_read(const char* path, char* buff, size_t buff_size, off_t offset, struct fuse_file_info* fi) {
    printf("[tabfs_read] path=%s, buff=%p, buff_size=%ld, offset=%ld\n", path, buff, buff_size, offset);

    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;

    libtabfs_entrytable_entry_t* entry = NULL;
    obtain_tabfs_entry(volume, path, &entry);

    unsigned long bytesRead = 0;
    libtabfs_read_file(volume, entry, offset, buff_size, buff, &bytesRead);

    return bytesRead;
}

int tabfs_write(const char* path, const char* buff, size_t buff_size, off_t offset, struct fuse_file_info* fi) {
    printf("[tabfs_write] path=%s, buff=%p, buff_size=%ld, offset=%ld\n", path, buff, buff_size, offset);

    libtabfs_volume_t* volume = (libtabfs_volume_t*) fuse_get_context()->private_data;

    libtabfs_entrytable_entry_t* entry = NULL;
    obtain_tabfs_entry(volume, path, &entry);

    unsigned long bytesWritten = 0;
    libtabfs_error err = libtabfs_write_file(volume, entry, offset, buff_size, buff, &bytesWritten);
    if (err != LIBTABFS_ERR_NONE) {
        printf("[tabfs_write] => failed write with error %s (%d)\n", libtabfs_errstr(err), err);
        return -EPERM;
    }

    // TODO: Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is expected to reset the setuid and setgid bits.

    return bytesWritten;
}

//--------------------------------------------------------------------------------
// Operations
//--------------------------------------------------------------------------------

const struct fuse_operations tabfs_oper = {
    .getattr = tabfs_getattr,
    // readlink
    .mknod = tabfs_mknod,
    .mkdir = tabfs_mkdir,
    // unlink
    .rmdir = tabfs_rmdir,
    // symlink
    .rename = tabfs_rename,
    // link
    .chmod = tabfs_chmod,
    .chown = tabfs_chown,
    // truncate
    // open
    .read = tabfs_read,
    .write = tabfs_write,
    // statfs
    .flush = tabfs_flush,
    // release
    // fsync
    // setxattr
    // getxattr
    // listxattr
    // removexattr
    .opendir = tabfs_opendir,
    .readdir = tabfs_readdir,
    .releasedir = tabfs_releasedir,
    .fsyncdir = tabfs_fsyncdir,
    .init = tabfs_init,
    .destroy = tabfs_destroy,
    .access = tabfs_access,
    // create -> mknod() + open()
    // lock
    .utimens = tabfs_utimens,
    // bmap
    .ioctl = tabfs_ioctl,
    // poll
    // write_buf
    // read_buf
    // flock
    // fallocate
    // copy_file_range
    // lseek
};