#define FUSE_USE_VERSION 31
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>

#include "options.h"
#include "operations.h"

#include <libtabfs/libtabfs.h>

// make our own fuse_main to control certain options (threading) better
int custom_fuse_main(int argc, char *argv[], const struct fuse_operations *op, size_t op_size, void *private_data) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse *fuse;
    struct fuse_cmdline_opts opts;
    int res;

    if (fuse_parse_cmdline(&args, &opts) != 0)
        return 1;

    if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        res = 0;
        goto out1;
    }

    if (opts.show_help) {
        if(args.argv[0][0] != '\0')
            printf("usage: %s [options] <mountpoint>\n\n",
                   args.argv[0]);
        printf("FUSE options:\n");
        fuse_cmdline_help();
        fuse_lib_help(&args);
        res = 0;
        goto out1;
    }

    if (!opts.show_help &&
        !opts.mountpoint) {
        fuse_log(FUSE_LOG_ERR, "error: no mountpoint specified\n");
        res = 2;
        goto out1;
    }

    //fuse = fuse_new_31(&args, op, op_size, NULL);
    fuse = fuse_new(&args, op, op_size, private_data);
    if (fuse == NULL) {
        res = 3;
        goto out1;
    }

    if (fuse_mount(fuse,opts.mountpoint) != 0) {
        res = 4;
        goto out2;
    }

    if (fuse_daemonize(opts.foreground) != 0) {
        res = 5;
        goto out3;
    }

    struct fuse_session *se = fuse_get_session(fuse);
    if (fuse_set_signal_handlers(se) != 0) {
        res = 6;
        goto out3;
    }

    res = fuse_loop(fuse);
    //if (opts.singlethread)
    //    res = fuse_loop(fuse);
    //else {
    //    struct fuse_loop_config loop_config;
    //    loop_config.clone_fd = opts.clone_fd;
    //    loop_config.max_idle_threads = opts.max_idle_threads;
    //    res = fuse_loop_mt_32(fuse, &loop_config);
    //}
    if (res)
        res = 7;

    fuse_remove_signal_handlers(se);
out3:
    fuse_unmount(fuse);
out2:
    fuse_destroy(fuse);
out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
    return res;
}

int main(int argc, char* argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1) {
        return 1;
    }

    if (options.devFile == NULL) {
        printf("Need devicefile to function! Please specify one with --dev\n");
        fuse_opt_free_args(&args);
        return 1;
    }

    {
        struct stat statBuffer;
        if ( stat(options.devFile, &statBuffer) != 0 ) {
            printf("Failed to find devicefile '%s'\n", options.devFile);
            fuse_opt_free_args(&args);
            return 1;
        }
    }

    FILE* devFile_handle = fopen(options.devFile, options.readonly ? "rb" : "r+b");
    if (devFile_handle == NULL) {
        if (options.readonly) {
            printf("Devicefile '%s' could not be opened for binary reading\n", options.devFile);
        }
        else {
            printf("Devicefile '%s' could not be opened for binary reading & writing\n", options.devFile);
        }
        printf("If you want an read-only filesystem, specify --readonly\n");
        fuse_opt_free_args(&args);
        return 1;
    }

    printf("Devicefile to use: %s\n", options.devFile);

    libtabfs_error err = libtabfs_new_volume(devFile_handle, 0x0, true, &gVolume);
    if (err != LIBTABFS_ERR_NONE) {
        printf("Recieved error while initializing tabfs volume: %d (%d)\n", libtabfs_errstr(err), err);
        fuse_opt_free_args(&args);
        return 1;
    }

    //int ret = fuse_main(args.argc, args.argv, &tabfs_oper, NULL);
    int ret = custom_fuse_main(args.argc, args.argv, &tabfs_oper, sizeof(tabfs_oper), gVolume);
    fuse_opt_free_args(&args);
    return ret;
}