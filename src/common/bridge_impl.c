#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libtabfs/common.h>
#include <string.h>
#include <time.h>

long calc_lba_offset(libtabfs_lba_28_t lba, bool is_absolute_lba) {
    long result = lba * 512;
    return result;
}

void my_dump_mem(uint8_t* mem, int size) {
    printf("\e[32m---- 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\e[0m\n");
    for (int i = 0; i < (size / 16); i++) {
        printf("\e[32m%04x\e[0m ", i * 0x10);
        for (int j = 0; j < 16; j++) {
            printf("%02x ", mem[i * 16 + j]);
        }
        for (int j = 0; j < 16; j++) {
            char c = mem[i * 16 + j];
            if (
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9')
            ) {
                printf("%c", c);
            }
            else {
                printf("\e[32m.\e[0m");
            }
        }
        printf("\n");
    }
}

void libtabfs_read_device(
    void* dev_data,
    libtabfs_lba_28_t lba, bool is_absolute_lba, int offset,
    void* buffer, int buffer_size
) {
    // printf("[libtabfs_read_device] lba: 0x%x, offset: %d, buffer_size: %d\n", lba, offset, buffer_size);
    // printf("[libtabfs_read_device]   fileoffset: %d\n", calc_lba_offset(lba, is_absolute_lba));

    fseek((FILE*) dev_data, calc_lba_offset(lba, is_absolute_lba) + offset, SEEK_SET);
    fread(buffer, sizeof(uint8_t), buffer_size, (FILE*) dev_data);

    // my_dump_mem(buffer, buffer_size);
}

void libtabfs_write_device(
    void* dev_data,
    libtabfs_lba_28_t lba, bool is_absolute_lba, int offset,
    void* buffer, int buffer_size
) {
    // printf("[libtabfs_write_device] lba: 0x%x, offset: %d, buffer_size: %d\n", lba, offset, buffer_size);
    // printf("[libtabfs_write_device]   fileoffset: %d\n", calc_lba_offset(lba, is_absolute_lba));
    // my_dump_mem(buffer, buffer_size);

    fseek((FILE*) dev_data, calc_lba_offset(lba, is_absolute_lba) + offset, SEEK_SET);
    fwrite(buffer, sizeof(uint8_t), buffer_size, (FILE*) dev_data);
}

void libtabfs_set_range_device(
    void* dev_data,
    libtabfs_lba_28_t lba, bool is_absolute_lba, int offset,
    unsigned char b, int size
) {
    fseek((FILE*) dev_data, calc_lba_offset(lba, is_absolute_lba) + offset, SEEK_SET);

    uint8_t* buff = (uint8_t*) malloc(size);
    memset(buff, b, size);
    fwrite(buff, sizeof(uint8_t), size, (FILE*) dev_data);
    free(buff);
}

int libtabfs_strlen(char* str) {
    return strlen(str);
}

char* libtabfs_strchr(char* str, char c) {
    return strchr(str, c);
}

int libtabfs_strcmp(char* a, char* b) {
    return strcmp(a, b);
}

void libtabfs_memcpy(void* dest, void* src, int count) {
    memcpy(dest, src, count);
}

void* libtabfs_alloc(int size) {
    return calloc(size, sizeof(uint8_t));
}

void libtabfs_free(void* ptr, int size) {
    free(ptr);
}

void libtabfs_get_current_time(long long* time) {
    time_t now;
    localtime(&now);
    *time = now;
}