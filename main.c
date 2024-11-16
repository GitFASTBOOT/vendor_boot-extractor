#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define VENDOR_BOOT_MAGIC    "VNDRBOOT"
#define VENDOR_BOOT_MAGIC_SIZE  8
#define VENDOR_BOOT_ARGS_SIZE 2048
#define VENDOR_BOOT_NAME_SIZE 16
#define VENDOR_HEADER_SIZE  2112

#define OUTPUT_DIR           "vendor_boot"
#define VENDOR_RAMDISK       "vendor_ramdisk.img"
#define RAMDISK_OUTPUT_NAME  "vendor_ramdisk.cpio"
#define VENDOR_DTB           "vendor_dtb.img"
#define DTB_OUTPUT_NAME      "dtb.img"
#define HEADER_INFO_FILE     "vendor_boot_header_info.txt"

#define PAGES(size, page_size)  (((size) + (page_size) - 1) / (page_size))
#define ALIGN(size, page_size)  ((PAGES(size, page_size)) * (page_size))

struct vendor_boot_img_hdr {
    uint8_t magic[VENDOR_BOOT_MAGIC_SIZE];
    uint32_t header_version;
    uint32_t page_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_addr;
    uint32_t vendor_ramdisk_size;
    uint8_t cmdline[VENDOR_BOOT_ARGS_SIZE];
    uint32_t tags_addr;
    uint8_t name[VENDOR_BOOT_NAME_SIZE];
    uint32_t header_size;
    uint32_t dtb_size;
    uint64_t dtb_addr;
};

static void print_usage(char *app)
{
    printf("Usage: %s <path to vendor_boot.img>\n", app);
}

static int parse_args(int argc, char *argv[], char **path)
{
    if (argc != 2) {
        fprintf(stderr, "Error: Invalid argument count\n");
        print_usage(argv[0]);
        return -1;
    }

    *path = argv[1];
    return 0;
}

static int file_read(void *ptr, size_t size, FILE *stream)
{
    size_t num;

    num = fread(ptr, size, 1, stream);
    if (num != 1) {
        fprintf(stderr, "Error: Can't read file\n");
        if (feof(stream))
            fprintf(stderr, "End of file reached\n");
        else if (ferror(stream))
            fprintf(stderr, "I/O error occurred\n");
        return -1;
    }

    return 0;
}

static int file_write(const void *ptr, size_t size, FILE *stream)
{
    size_t num;

    num = fwrite(ptr, size, 1, stream);
    if (num != 1) {
        fprintf(stderr, "Error: Can't write file\n");
        if (feof(stream))
            fprintf(stderr, "End of file reached\n");
        else if (ferror(stream))
            fprintf(stderr, "I/O error occurred\n");
        return -1;
    }

    return 0;
}

static int create_output_dir()
{
    struct stat st = {0};
    if (stat(OUTPUT_DIR, &st) == -1) {
        if (mkdir(OUTPUT_DIR, 0755) != 0) {
            perror("Error creating output directory");
            return -1;
        }
    }
    return 0;
}

static int write_header_info_to_file(struct vendor_boot_img_hdr *hdr)
{
    FILE *f_info;
    char info_path[256];

    snprintf(info_path, sizeof(info_path), "%s/%s", OUTPUT_DIR, HEADER_INFO_FILE);
    f_info = fopen(info_path, "w");
    if (!f_info) {
        fprintf(stderr, "Error: Can't open %s file for writing; reason: %s\n",
            info_path, strerror(errno));
        return -1;
    }

    fprintf(f_info, "Kernel Base:0x%08x\n", hdr->kernel_addr);
    fprintf(f_info, "Page Size:%u\n", hdr->page_size);
    fprintf(f_info, "Kernel Offset:0x%08x\n", hdr->kernel_addr);
    fprintf(f_info, "Ramdisk Offset:0x%08x\n", hdr->ramdisk_addr);
    fprintf(f_info, "Tags Offset:0x%08x\n", hdr->tags_addr);
    fprintf(f_info, "Boot Header Version:%u\n", hdr->header_version);
    fprintf(f_info, "DTB Size:%u\n", hdr->dtb_size);
    fprintf(f_info, "DTB Offset:0x%08llx\n", hdr->dtb_addr);
    fprintf(f_info, "Header Size:%u\n", hdr->header_size);
    fprintf(f_info, "Vendor Cmdline:%s\n", hdr->cmdline);

    fclose(f_info);
    return 0;
}

int main(int argc, char *argv[])
{
    char *img_path;
    FILE *f_vbi, *f_wr;
    struct vendor_boot_img_hdr hdr;
    int ret = EXIT_FAILURE;
    int err;
    long size_hdr, size_rd;
    uint8_t *buf;

    err = parse_args(argc, argv, &img_path);
    if (err)
        return EXIT_SUCCESS;

    if (create_output_dir() != 0)
        return EXIT_FAILURE;

    f_vbi = fopen(img_path, "r");
    if (!f_vbi) {
        fprintf(stderr, "Error: Can't open %s file; reason: %s\n",
            img_path, strerror(errno));
        return EXIT_FAILURE;
    }

    printf("--> Reading ramdisk...\n--> Reading dtb...\n--> Reading header...\n");
    err = file_read(&hdr, sizeof(hdr), f_vbi);
    if (err)
        goto err1;

    size_hdr = ALIGN(VENDOR_HEADER_SIZE, hdr.page_size);
    err = fseek(f_vbi, size_hdr, SEEK_SET);
    if (err) {
        fprintf(stderr, "Error: Can't seek %s file; reason: %s\n",
            img_path, strerror(errno));
        goto err1;
    }

    // Read ramdisk
    buf = malloc(hdr.vendor_ramdisk_size);
    err = file_read(buf, hdr.vendor_ramdisk_size, f_vbi);
    if (err)
        goto err2;

    char ramdisk_path[256];
    snprintf(ramdisk_path, sizeof(ramdisk_path), "%s/%s", OUTPUT_DIR, RAMDISK_OUTPUT_NAME);

    f_wr = fopen(ramdisk_path, "w");
    if (!f_wr) {
        fprintf(stderr, "Error: Can't open %s file; reason: %s\n",
            ramdisk_path, strerror(errno));
        goto err2;
    }
    err = file_write(buf, hdr.vendor_ramdisk_size, f_wr);
    if (err)
        goto err3;
    fclose(f_wr);
    free(buf);

    size_rd = ALIGN(hdr.vendor_ramdisk_size, hdr.page_size);
    err = fseek(f_vbi, size_hdr + size_rd, SEEK_SET);
    if (err) {
        fprintf(stderr, "Error: Can't seek %s file; reason: %s\n",
            img_path, strerror(errno));
        goto err1;
    }

    // Read dtb
    buf = malloc(hdr.dtb_size);
    err = file_read(buf, hdr.dtb_size, f_vbi);
    if (err)
        goto err2;

    char dtb_path[256];
    snprintf(dtb_path, sizeof(dtb_path), "%s/%s", OUTPUT_DIR, DTB_OUTPUT_NAME);

    f_wr = fopen(dtb_path, "w");
    if (!f_wr) {
        fprintf(stderr, "Error: Can't open %s file; reason: %s\n",
            dtb_path, strerror(errno));
        goto err2;
    }
    err = file_write(buf, hdr.dtb_size, f_wr);
    if (err)
        goto err3;

    // Write header information to a text file
    err = write_header_info_to_file(&hdr);
    if (err)
        goto err3;

    printf("Files extracted to %s\n", OUTPUT_DIR);
    printf("Kernel Base:0x%08x\nPage Size:%u\nKernel Offset:0x%08x\nRamdisk Offset:0x%08x\nTags Offset:0x%08x\nBoot Header Version:%u\nDTB Size:%u\nDTB Offset:0x%08llx\nHeader Size:%u\nVendor Cmdline:%s\n", 
        hdr.kernel_addr, hdr.page_size, hdr.kernel_addr, hdr.ramdisk_addr, hdr.tags_addr, hdr.header_version, hdr.dtb_size, hdr.dtb_addr, hdr.header_size, hdr.cmdline);

    ret = EXIT_SUCCESS;

err3:
    fclose(f_wr);
err2:
    free(buf);
err1:
    fclose(f_vbi);
    return ret;
}

