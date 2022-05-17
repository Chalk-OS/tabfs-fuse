#include <stdio.h>
#include <libtabfs/libtabfs.h>

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("Usage: make_test_img <filename>\n");
        return 1;
    }

    printf("Creating testimage in file: %s\n", argv[1]);

    struct stat* statBuffer;
    if (stat(argv[1], &statBuffer) == 0) {
        printf("Can only create testimage on new file, but '%s' already exists\n", argv[1]);
        return 1;
    }

    FILE* f = fopen(argv[1], "wb");
    if (f == NULL) {
        printf("Cannot open file to write to...\n");
        return 1;
    }

    /*
        The testimage should be 1MB big; this means for us, 2048 blocks; this in turns mean 256 occupied bytes in an bat.
        Since a bat has 512 bytes (minus 6 for its metadata), we can store the whole BAT in one block & one section.

        Layout of the testimage:

        0x0       : header
        0x1       : volume information
        0x2       : BAT
        0x3 - 0x6 : root entrytable
    */

    // write an header
    {
        fseek(f, 0x1C0, SEEK_SET);
        fwrite("TABFS-28", sizeof(char), 8, f);
        fseek(f, 8 + 32, SEEK_CUR);

        unsigned short flags = 0x0000;
        fwrite(&flags, sizeof(unsigned short), 1, f);

        fseek(f, 4, SEEK_CUR);

        libtabfs_lba_48_t volInfLba = { .i64 = 0x1 };
        fwrite(&volInfLba, sizeof(libtabfs_lba_48_t), 1, f);

        unsigned short bootsig = 0xAA55;
        fwrite(&bootsig, sizeof(unsigned short), 1, f);
    }

    // write an volume information block
    {
        fwrite("TABFS-28", sizeof(char), 8, f);
        fseek(f, 8, SEEK_CUR);

        libtabfs_lba_28_t batLba = 0x02;
        fwrite(&batLba, sizeof(libtabfs_lba_28_t), 1, f);

        libtabfs_lba_28_t minLba = 0x00;
        fwrite(&minLba, sizeof(libtabfs_lba_28_t), 1, f);

        libtabfs_lba_28_t batStartLba = 0x02;
        fwrite(&batStartLba, sizeof(libtabfs_lba_28_t), 1, f);

        libtabfs_lba_28_t maxLba = 0x0800;
        fwrite(&maxLba, sizeof(libtabfs_lba_28_t), 1, f);

        unsigned int blockSize = 512;
        fwrite(&blockSize, sizeof(unsigned int), 1, f);

        unsigned char BS = 1;
        fwrite(&blockSize, sizeof(unsigned char), 1, f);

        fseek(f, 1, SEEK_CUR);

        unsigned short flags = 0x0000;
        fwrite(&flags, sizeof(unsigned short), 1, f);

        libtabfs_lba_28_t rootLba = 0x03;
        fwrite(&rootLba, sizeof(libtabfs_lba_28_t), 1, f);

        unsigned int rootSize = 512 * 4;
        fwrite(&rootSize, sizeof(unsigned int), 1, f);

        fseek(f, 32, SEEK_CUR);

        // write an label!
        const char* label = "Tabfs testimage volume (1MB)";
        fwrite(label, sizeof(char), strlen(label), f);
    }

    // write the BAT
    fseek(f, 512 * 0x2, SEEK_SET);
    {
        libtabfs_lba_28_t next_bat = 0x0;
        fwrite(&next_bat, sizeof(libtabfs_lba_28_t), 1, f);

        unsigned short blockCount = 1;
        fwrite(&blockCount, sizeof(unsigned short), 1, f);

        // write the BAT's data!
        unsigned char data = 0b11111110;
        fwrite(&data, sizeof(unsigned char), 1, f);
    }

    // write the root entrytable
    fseek(f, 512 * 0x3, SEEK_SET);
    {
        unsigned char type = LIBTABFS_ENTRYTYPE_TABLEINFO;
        fwrite(&type, sizeof(unsigned char), 1, f);
        fseek(f, 63, SEEK_CUR);

        // TODO: add another entry to verifying loading or something...
    }

    // make the image file big enough
    fseek(f, (512 * 2048) - 1, SEEK_SET);
    unsigned char unused = 0x00;
    fwrite(&unused, sizeof(unsigned char), 1, f);

    fclose(f);
    return 0;
}