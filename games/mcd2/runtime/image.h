#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct ImageLayout {
    uint64_t patch_off, key_off, text_end, ro_off, data_off, symbol_count;
    int has_symbol_count;
} ImageLayout;

typedef struct Image {
    char name[32];
    uint8_t *base;
    size_t mapped;
    uint64_t key_off, text_end, ro_off, data_off, patch_off, init;
    unsigned relative, symbolic, unresolved, symbols;
    void *detail;
} Image;

int image_read_fixups(const char *path, ImageLayout *layout);
int image_bind(Image *image, const char *name, uint8_t *base, size_t mapped, const ImageLayout *layout);
int image_relocate(Image *images, int count, void *unresolved, void *nnmain_wrapper, void **nnmain_real);
void *image_symbol(Image *images, int count, const char *name, Image **owner, uint64_t *offset);
void image_dispose(Image *image);
