add_rules('mode.debug')
add_rules('mode.release')

target("tabfs")
    set_kind("binary")
    add_files("src/tabfs_fuse/*.c", "src/common/*.c")
    add_defines("_FILE_OFFSET_BITS=64")
    add_links("fuse3", "tabfs")

target("make_test_img")
    set_default(false)
    set_kind("binary")
    add_files("src/utils/make_test_img.c", "src/common/*.c")
    add_defines("_FILE_OFFSET_BITS=64")
    add_links("tabfs")