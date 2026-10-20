#include "image.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: image_check <patched.bin> <fixups.tsv> <reloc-offset> <addend>\n");
        return 2;
    }
    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) return 1;
    uint8_t *base = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return 1;
    ImageLayout layout;
    Image image;
    if (image_read_fixups(argv[2], &layout) || image_bind(&image, "main", base, (size_t)st.st_size, &layout))
        return 1;
    static char sink;
    if (image_relocate(&image, 1, &sink, NULL, NULL)) return 1;
    uint64_t where = strtoull(argv[3], NULL, 0);
    uint64_t addend = strtoull(argv[4], NULL, 0);
    uint64_t stored;
    memcpy(&stored, base + where, 8);
    if (stored != (uintptr_t)base + addend) {
        fprintf(stderr, "[mcd2] relative reloc mismatch\n");
        return 1;
    }
    fprintf(stderr, "[mcd2] relative reloc ok\n");
    image_dispose(&image);
    return 0;
}
