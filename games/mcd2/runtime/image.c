#include "image.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYM_CAP 1000000u

typedef struct {
    const char *name;
    uint64_t value;
    unsigned defined;
    unsigned binding;
} Sym;

typedef struct {
    Sym *syms;
    unsigned nsym;
    const uint8_t *dynstr;
    uint64_t dynstr_size;
} Detail;

static int fail(const char *message) {
    fprintf(stderr, "[mcd2] %s\n", message);
    return -1;
}

static uint32_t ru32(const uint8_t *p) {
    uint32_t value;
    memcpy(&value, p, 4);
    return value;
}

static int32_t ri32(const uint8_t *p) {
    int32_t value;
    memcpy(&value, p, 4);
    return value;
}

static uint64_t ru64(const uint8_t *p) {
    uint64_t value;
    memcpy(&value, p, 8);
    return value;
}

static int64_t ri64(const uint8_t *p) {
    int64_t value;
    memcpy(&value, p, 8);
    return value;
}

int image_read_fixups(const char *path, ImageLayout *layout) {
    FILE *file = fopen(path, "r");
    if (!file) return fail("cannot open fixups");
    memset(layout, 0, sizeof *layout);
    char line[256];
    while (fgets(line, sizeof line, file)) {
        char *cursor = line;
        if (*cursor != '#') break;
        cursor++;
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        char *key = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\n') cursor++;
        if (*cursor) *cursor++ = 0;
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        char *end = NULL;
        unsigned long long value = strtoull(cursor, &end, 0);
        if (end == cursor) {
            fclose(file);
            return fail("bad fixups value");
        }
        if (!strcmp(key, "PATCH_OFF")) layout->patch_off = value;
        else if (!strcmp(key, "KEY_PAGE_OFF")) layout->key_off = value;
        else if (!strcmp(key, "TEXT_END")) layout->text_end = value;
        else if (!strcmp(key, "RO_OFF")) layout->ro_off = value;
        else if (!strcmp(key, "DATA_OFF")) layout->data_off = value;
        else if (!strcmp(key, "SYMBOL_COUNT")) {
            layout->symbol_count = value;
            layout->has_symbol_count = 1;
        }
    }
    fclose(file);
    if (!layout->key_off) return fail("fixups missing KEY_PAGE_OFF");
    return 0;
}

static const char *dyn_string(const Detail *detail, uint32_t offset) {
    if ((uint64_t)offset >= detail->dynstr_size) return NULL;
    const uint8_t *text = detail->dynstr + offset;
    size_t room = (size_t)(detail->dynstr_size - offset);
    size_t length = 0;
    while (length < room && text[length] != 0) length++;
    if (length == room) return NULL;
    return (const char *)text;
}

int image_bind(Image *image, const char *name, uint8_t *base, size_t mapped, const ImageLayout *layout) {
    memset(image, 0, sizeof *image);
    if (snprintf(image->name, sizeof image->name, "%s", name) >= (int)sizeof image->name)
        return fail("module name too long");
    if (mapped < 8 || layout->key_off > mapped || layout->data_off >= layout->key_off)
        return fail("module layout does not fit the image");
    uint32_t modoff = ru32(base + 4);
    if ((uint64_t)modoff + 8 > layout->key_off || memcmp(base + modoff, "MOD0", 4) != 0)
        return fail("expected MOD0");
    uint64_t dyn = (uint64_t)((int64_t)modoff + ri32(base + modoff + 4));
    uint64_t tags[64];
    int present[64] = {0};
    for (int index = 0; index < 4096; index++) {
        if (dyn + 16 > layout->key_off) return fail("dynamic table outside the image");
        int64_t tag = ri64(base + dyn);
        uint64_t value = ru64(base + dyn + 8);
        dyn += 16;
        if (tag == 0) break;
        if (tag > 0 && tag < 64) {
            tags[tag] = value;
            present[tag] = 1;
        }
    }
    if (!present[5] || !present[6] || !present[10] || !present[11] || tags[11] != 24)
        return fail("dynamic table lacks ELF64 symbols");
    unsigned count = 0;
    if (present[4]) {
        if (tags[4] + 8 > layout->key_off) return fail("hash table outside the image");
        count = ru32(base + tags[4] + 4);
    }
    if (layout->has_symbol_count) {
        if (count && count != layout->symbol_count) return fail("symbol count does not match DT_HASH");
        if (!count) count = (unsigned)layout->symbol_count;
    }
    if (!count || count > SYM_CAP) return fail("symbol count missing or too large");
    if (tags[5] + tags[10] > layout->key_off || tags[6] + (uint64_t)count * 24 > layout->key_off)
        return fail("symbol table outside the image");
    Detail *detail = calloc(1, sizeof *detail);
    if (!detail) return fail("out of memory");
    detail->syms = calloc(count, sizeof(Sym));
    if (!detail->syms) {
        free(detail);
        return fail("out of memory");
    }
    detail->nsym = count;
    detail->dynstr = base + tags[5];
    detail->dynstr_size = tags[10];
    for (unsigned index = 0; index < count; index++) {
        const uint8_t *row = base + tags[6] + index * 24;
        uint32_t name_off = ru32(row);
        unsigned info = row[4];
        unsigned section = (unsigned)row[6] | ((unsigned)row[7] << 8);
        detail->syms[index].name = dyn_string(detail, name_off);
        detail->syms[index].value = ru64(row + 8);
        detail->syms[index].defined = section != 0;
        detail->syms[index].binding = info >> 4;
        if (!detail->syms[index].name) {
            free(detail->syms);
            free(detail);
            return fail("unterminated dynstr");
        }
    }
    image->base = base;
    image->mapped = mapped;
    image->key_off = layout->key_off;
    image->text_end = layout->text_end;
    image->ro_off = layout->ro_off;
    image->data_off = layout->data_off;
    image->patch_off = layout->patch_off;
    image->init = present[12] ? tags[12] : 0;
    image->symbols = count;
    image->detail = detail;
    return 0;
}

static int apply_one(Image *images, int count, Image *image, uint64_t where, uint32_t type,
                     uint32_t symbol, int64_t addend, void *unresolved, void *nnmain_wrapper,
                     void **nnmain_real) {
    if (where < image->data_off || where + 8 > image->key_off) return fail("relocation outside data");
    uintptr_t value = 0;
    if (type == 1027) {
        if (addend < 0 || (uint64_t)addend >= image->key_off) return fail("relative addend outside the module");
        value = (uintptr_t)image->base + (uint64_t)addend;
        image->relative++;
    } else if (type == 257 || type == 1025 || type == 1026) {
        Detail *detail = image->detail;
        if (symbol >= detail->nsym) return fail("relocation symbol out of range");
        Sym *sym = &detail->syms[symbol];
        void *target = NULL;
        if (sym->defined && sym->value < image->key_off) target = image->base + sym->value;
        else if (sym->name[0]) {
            for (int module = 0; module < count && !target; module++) {
                Detail *other = images[module].detail;
                for (unsigned index = 0; index < other->nsym; index++) {
                    Sym *candidate = &other->syms[index];
                    if (candidate->defined && !strcmp(candidate->name, sym->name) &&
                        candidate->value < images[module].key_off) {
                        target = images[module].base + candidate->value;
                        break;
                    }
                }
            }
        }
        if (type == 1026 && nnmain_wrapper && sym->name[0] && !strcmp(sym->name, "nnMain")) {
            if (nnmain_real && target) *nnmain_real = target;
            target = nnmain_wrapper;
        }
        if (!target) {
            if (sym->binding != 2) {
                fprintf(stderr, "[mcd2] unresolved %s %s\n", image->name, sym->name);
                image->unresolved++;
                target = unresolved;
            }
        }
        if (target) value = (uintptr_t)target + (type == 1026 ? 0 : (uintptr_t)addend);
        image->symbolic++;
    } else {
        return fail("unsupported relocation");
    }
    memcpy(image->base + where, &value, 8);
    return 0;
}

static int apply_rela(Image *images, int count, Image *image, uint64_t table, uint64_t size,
                      void *unresolved, void *nnmain_wrapper, void **nnmain_real) {
    if (!table || !size) return 0;
    if (size % 24 || table + size > image->key_off) return fail("relocation table outside the image");
    for (uint64_t offset = 0; offset < size; offset += 24) {
        const uint8_t *row = image->base + table + offset;
        uint64_t where = ru64(row);
        uint64_t info = ru64(row + 8);
        int64_t addend = ri64(row + 16);
        if (apply_one(images, count, image, where, (uint32_t)info, (uint32_t)(info >> 32), addend,
                      unresolved, nnmain_wrapper, nnmain_real))
            return -1;
    }
    return 0;
}

static int apply_relr(Image *image, uint64_t table, uint64_t size, uint64_t ent) {
    if (!table && !size) return 0;
    if (ent != 8 || size % 8 || table + size > image->key_off) return fail("invalid RELR table");
    uint64_t cursor = 0;
    int have_cursor = 0;
    for (uint64_t offset = 0; offset < size; offset += 8) {
        uint64_t entry = ru64(image->base + table + offset);
        if ((entry & 1) == 0) {
            if (entry + 8 > image->key_off) return fail("RELR address outside the image");
            int64_t addend = (int64_t)ru64(image->base + entry);
            if (apply_one(NULL, 0, image, entry, 1027, 0, addend, NULL, NULL, NULL)) return -1;
            cursor = entry + 8;
            have_cursor = 1;
        } else {
            if (!have_cursor) return fail("RELR bitmap before an address");
            for (int bit = 1; bit < 64; bit++) {
                if (entry & (1ull << bit)) {
                    uint64_t where = cursor + (uint64_t)(bit - 1) * 8;
                    if (where >= image->key_off || where + 8 > image->key_off)
                        return fail("RELR address outside the image");
                    int64_t addend = (int64_t)ru64(image->base + where);
                    if (apply_one(NULL, 0, image, where, 1027, 0, addend, NULL, NULL, NULL)) return -1;
                }
            }
            cursor += 63 * 8;
        }
    }
    return 0;
}

int image_relocate(Image *images, int count, void *unresolved, void *nnmain_wrapper, void **nnmain_real) {
    for (int module = 0; module < count; module++) {
        Image *image = &images[module];
        uint32_t modoff = ru32(image->base + 4);
        uint64_t dyn = (uint64_t)((int64_t)modoff + ri32(image->base + modoff + 4));
        uint64_t rela = 0, relasz = 0, jmprel = 0, pltrelsz = 0, relr = 0, relrsz = 0, relrent = 0;
        for (int index = 0; index < 4096; index++) {
            if (dyn + 16 > image->key_off) return fail("dynamic table outside the image");
            int64_t tag = ri64(image->base + dyn);
            uint64_t value = ru64(image->base + dyn + 8);
            dyn += 16;
            if (tag == 0) break;
            if (tag == 7) rela = value;
            else if (tag == 8) relasz = value;
            else if (tag == 23) jmprel = value;
            else if (tag == 2) pltrelsz = value;
            else if (tag == 36) relr = value;
            else if (tag == 35) relrsz = value;
            else if (tag == 37) relrent = value;
        }
        Detail *detail = image->detail;
        for (unsigned index = 0; index < detail->nsym; index++) {
            Sym *sym = &detail->syms[index];
            if (sym->defined && !strcmp(sym->name, "nnMain") && nnmain_real && !*nnmain_real &&
                sym->value < image->key_off)
                *nnmain_real = image->base + sym->value;
        }
        if (apply_relr(image, relr, relrsz, relrent)) return -1;
        if (apply_rela(images, count, image, rela, relasz, unresolved, nnmain_wrapper, nnmain_real)) return -1;
        if (apply_rela(images, count, image, jmprel, pltrelsz, unresolved, nnmain_wrapper, nnmain_real)) return -1;
        fprintf(stderr, "[mcd2] relocated %s relative=%u symbolic=%u unresolved=%u\n",
                image->name, image->relative, image->symbolic, image->unresolved);
    }
    return 0;
}

void *image_symbol(Image *images, int count, const char *name, Image **owner, uint64_t *offset) {
    for (int module = 0; module < count; module++) {
        Detail *detail = images[module].detail;
        for (unsigned index = 0; index < detail->nsym; index++) {
            Sym *sym = &detail->syms[index];
            if (sym->defined && sym->name[0] && !strcmp(sym->name, name) && sym->value < images[module].key_off) {
                if (owner) *owner = &images[module];
                if (offset) *offset = sym->value;
                return images[module].base + sym->value;
            }
        }
    }
    return NULL;
}

void image_dispose(Image *image) {
    Detail *detail = image->detail;
    if (!detail) return;
    free(detail->syms);
    free(detail);
    image->detail = NULL;
}
