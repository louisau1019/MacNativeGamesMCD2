#define _POSIX_C_SOURCE 200809L
#include "image.h"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__) && defined(__aarch64__)
#include <pthread.h>
#include <ucontext.h>
void runtime_gate(void);
static pthread_key_t thread_slots[8];
#endif

static const char *START = "_ZN2nn4init5StartEmmPFvvES2_S2_";

static Image *images;
static int image_count;
static char (*gate_lines)[4][32];
static int gate_count;
static void (*real_nnmain)(void);

static int fail(const char *message) {
    fprintf(stderr, "[mcd2] %s\n", message);
    return -1;
}

static void append(char *out, size_t cap, size_t *used, const char *text) {
    while (*text && *used + 1 < cap) out[(*used)++] = *text++;
    out[*used] = 0;
}

static void append_hex(char *out, size_t cap, size_t *used, uint64_t value) {
    char tmp[16];
    int n = 0;
    append(out, cap, used, "0x");
    if (!value) {
        append(out, cap, used, "0");
        return;
    }
    while (value && n < 16) {
        tmp[n++] = "0123456789abcdef"[value & 15];
        value >>= 4;
    }
    while (n && *used + 1 < cap) out[(*used)++] = tmp[--n];
    out[*used] = 0;
}

static void describe(uint64_t address, char *out, size_t cap) {
    size_t used = 0;
    out[0] = 0;
    for (int index = 0; index < image_count; index++) {
        uintptr_t base = (uintptr_t)images[index].base;
        if (address >= base && address < base + images[index].mapped) {
            append(out, cap, &used, images[index].name);
            append(out, cap, &used, "+");
            append_hex(out, cap, &used, address - base);
            return;
        }
    }
    append_hex(out, cap, &used, address);
}

#if defined(__APPLE__) && defined(__aarch64__)
static void on_fault(int signal_number, siginfo_t *info, void *context) {
    char where[96];
    char message[160];
    size_t used = 0;
    ucontext_t *context_words = context;
    uint64_t pc = context_words->uc_mcontext->__ss.__pc;
    (void)info;
    describe(pc, where, sizeof where);
    append(message, sizeof message, &used, "[mcd2] fault signal ");
    append_hex(message, sizeof message, &used, (uint64_t)signal_number);
    append(message, sizeof message, &used, " at ");
    append(message, sizeof message, &used, where);
    append(message, sizeof message, &used, "\n");
    if (write(2, message, used) < 0) _exit(128 + signal_number);
    _exit(128 + signal_number);
}
#endif

void runtime_on_gate(uint64_t return_address) {
    char where[96];
    char message[192];
    size_t used = 0;
    describe(return_address, where, sizeof where);
    append(message, sizeof message, &used, "[mcd2] gate ");
    append(message, sizeof message, &used, where);
    for (int index = 0; index < gate_count; index++) {
        unsigned long long offset = strtoull(gate_lines[index][0], NULL, 0);
        for (int module = 0; module < image_count; module++) {
            if ((uintptr_t)images[module].base + offset == return_address) {
                append(message, sizeof message, &used, " kind=");
                append(message, sizeof message, &used, gate_lines[index][1]);
                append(message, sizeof message, &used, " arg=");
                append(message, sizeof message, &used, gate_lines[index][2]);
                append(message, sizeof message, &used, " original=");
                append(message, sizeof message, &used, gate_lines[index][3]);
                goto done;
            }
        }
    }
    append(message, sizeof message, &used, " not in gates.tsv");
done:
    append(message, sizeof message, &used, "\n");
    if (write(2, message, used) < 0) _exit(4);
    _exit(4);
}

static void wrapped_nnmain(void) {
    fprintf(stderr, "[mcd2] ENTER nnMain\n");
    fflush(stderr);
    if (!real_nnmain) {
        fprintf(stderr, "[mcd2] nnMain has no definition\n");
        _exit(5);
    }
    real_nnmain();
    fprintf(stderr, "[mcd2] RETURN nnMain\n");
}

#if defined(__APPLE__) && defined(__aarch64__)
static void modules_linked(void) {
    fprintf(stderr, "[mcd2] rtld callback: modules linked\n");
}

static void run_inits(void) {
    fprintf(stderr, "[mcd2] running DT_INIT\n");
    for (int index = 0; index < image_count; index++) {
        if (!images[index].init || !strcmp(images[index].name, "rtld")) {
            if (!strcmp(images[index].name, "rtld"))
                fprintf(stderr, "[mcd2] skip DT_INIT rtld\n");
            continue;
        }
        fprintf(stderr, "[mcd2] ENTER %s DT_INIT\n", images[index].name);
        ((void (*)(void))(images[index].base + images[index].init))();
        fprintf(stderr, "[mcd2] RETURN %s DT_INIT\n", images[index].name);
    }
}

static void guest_returned(void) {
    fprintf(stderr, "[mcd2] guest returned from nn::init::Start\n");
}
#endif

static int load_gates(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    char line[256];
    while (fgets(line, sizeof line, file)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *fields[4] = {0};
        int count = 0;
        char *cursor = line;
        while (count < 4 && *cursor) {
            while (*cursor == ' ' || *cursor == '\t') cursor++;
            if (*cursor == '\n' || !*cursor) break;
            fields[count++] = cursor;
            while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\n') cursor++;
            if (*cursor) *cursor++ = 0;
        }
        if (count != 4) {
            fclose(file);
            return fail("bad gates.tsv line");
        }
        char (*next)[4][32] = realloc(gate_lines, (size_t)(gate_count + 1) * sizeof *gate_lines);
        if (!next) {
            fclose(file);
            return fail("out of memory");
        }
        gate_lines = next;
        for (int field = 0; field < 4; field++)
            snprintf(gate_lines[gate_count][field], 32, "%s", fields[field]);
        gate_count++;
    }
    fclose(file);
    return 0;
}

static int map_one(const char *dir, const char *name) {
    char path[4096], fixups[4096], gates[4096];
    if (snprintf(path, sizeof path, "%s/%s.patched.bin", dir, name) >= (int)sizeof path) return fail("path too long");
    if (snprintf(fixups, sizeof fixups, "%s/%s.fixups.tsv", dir, name) >= (int)sizeof fixups) return fail("path too long");
    if (snprintf(gates, sizeof gates, "%s/%s.gates.tsv", dir, name) >= (int)sizeof gates) return fail("path too long");
    int fd = open(path, O_RDONLY);
    if (fd < 0) return fail("cannot open patched module");
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return fail("patched module size");
    }
    uint8_t *base = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return fail("map module");
    ImageLayout layout;
    if (image_read_fixups(fixups, &layout)) return -1;
    Image *next = realloc(images, (size_t)(image_count + 1) * sizeof *images);
    if (!next) return fail("out of memory");
    images = next;
    if (image_bind(&images[image_count], name, base, (size_t)st.st_size, &layout)) return -1;
    image_count++;
    if (load_gates(gates)) return -1;
    fprintf(stderr, "[mcd2] mapped %s size=%zu symbols=%u\n", name, (size_t)st.st_size,
            images[image_count - 1].symbols);
    return 0;
}

static int preferred(const char *name) {
    if (!strcmp(name, "main")) return 0;
    if (!strcmp(name, "sdk")) return 1;
    if (!strcmp(name, "subsdk0")) return 2;
    return 3;
}

static int map_directory(const char *dir) {
    DIR *handle = opendir(dir);
    if (!handle) return fail("cannot open rewritten directory");
    char names[32][32];
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(handle))) {
        size_t length = strlen(entry->d_name);
        if (length < strlen(".patched.bin") || strcmp(entry->d_name + length - 12, ".patched.bin")) continue;
        if (length - 12 >= sizeof names[0] || count == 32) {
            closedir(handle);
            return fail("too many modules");
        }
        memcpy(names[count], entry->d_name, length - 12);
        names[count][length - 12] = 0;
        count++;
    }
    closedir(handle);
    if (!count) return fail("no patched modules");
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            int order = preferred(names[i]) - preferred(names[j]);
            if (order > 0 || (order == 0 && strcmp(names[i], names[j]) > 0)) {
                char tmp[32];
                memcpy(tmp, names[i], 32);
                memcpy(names[i], names[j], 32);
                memcpy(names[j], tmp, 32);
            }
        }
    }
    for (int index = 0; index < count; index++) {
        if (map_one(dir, names[index])) return -1;
    }
    return 0;
}

#if defined(__APPLE__) && defined(__aarch64__)
static int install_slots(void) {
    for (int index = 0; index < 8; index++) {
        if (pthread_key_create(&thread_slots[index], NULL) != 0 || thread_slots[index] == 0)
            return fail("pthread key");
    }
    if (pthread_setspecific(thread_slots[3], (void *)runtime_gate) != 0) return fail("gate slot");
    for (int module = 0; module < image_count; module++) {
        if (images[module].key_off + 64 > images[module].patch_off ||
            images[module].patch_off > images[module].mapped)
            return fail("key page overlaps the patch");
        uint64_t *page = (uint64_t *)(images[module].base + images[module].key_off);
        for (int index = 0; index < 8; index++) page[index] = (uint64_t)thread_slots[index] * 8;
    }
    uintptr_t thread_pointer;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(thread_pointer));
    if (thread_pointer & 7) return fail("Darwin thread pointer is unaligned");
    void *stored;
    memcpy(&stored, (void *)(thread_pointer + (uint64_t)thread_slots[3] * 8), sizeof stored);
    if (stored != (void *)runtime_gate) return fail("Darwin thread slot layout rejected");
    return 0;
}
#endif

#if defined(__APPLE__) && defined(__aarch64__)
static void protect_image(const Image *image) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return;
    size_t text = ((size_t)image->text_end + (size_t)page - 1) & ~((size_t)page - 1);
    if (text && text <= image->mapped)
        mprotect(image->base, text, PROT_READ | PROT_EXEC);
    if (image->patch_off < image->mapped) {
        size_t patch = image->patch_off & ~((size_t)page - 1);
        mprotect(image->base + patch, image->mapped - patch, PROT_READ | PROT_EXEC);
    }
}
#endif

static int report_entry(int call) {
    Image *owner = NULL;
    uint64_t offset = 0;
    void *start = image_symbol(images, image_count, START, &owner, &offset);
    if (start) {
        fprintf(stderr, "[mcd2] entry nn::init::Start %s+0x%llx\n", owner->name, (unsigned long long)offset);
        if (!call) return 0;
#if defined(__APPLE__) && defined(__aarch64__)
        if (install_slots()) return -1;
        for (int index = 0; index < image_count; index++) protect_image(&images[index]);
        struct sigaction action = {0};
        action.sa_sigaction = on_fault;
        action.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &action, NULL);
        sigaction(SIGBUS, &action, NULL);
        sigaction(SIGILL, &action, NULL);
        fprintf(stderr, "[mcd2] ENTER nn::init::Start\n");
        ((void (*)(uint64_t, uint64_t, void (*)(void), void (*)(void), void (*)(void)))start)(
            0, 0, modules_linked, run_inits, guest_returned);
        fprintf(stderr, "[mcd2] RETURN nn::init::Start\n");
        return 0;
#else
        fprintf(stderr, "[mcd2] mapped and entry resolved; not calling (this host is not Apple silicon)\n");
        return 0;
#endif
    }
    void *nnmain = image_symbol(images, image_count, "nnMain", &owner, &offset);
    if (!nnmain) {
        fprintf(stderr, "[mcd2] no entry symbol nn::init::Start or nnMain\n");
        return 5;
    }
    fprintf(stderr, "[mcd2] entry nnMain %s+0x%llx\n", owner->name, (unsigned long long)offset);
    if (!call) return 0;
#if defined(__APPLE__) && defined(__aarch64__)
    if (install_slots()) return -1;
    for (int index = 0; index < image_count; index++) protect_image(&images[index]);
    struct sigaction action = {0};
    action.sa_sigaction = on_fault;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGBUS, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    fprintf(stderr, "[mcd2] ENTER nnMain\n");
    ((void (*)(void))nnmain)();
    fprintf(stderr, "[mcd2] RETURN nnMain\n");
    return 0;
#else
    fprintf(stderr, "[mcd2] mapped and entry resolved; not calling (this host is not Apple silicon)\n");
    return 0;
#endif
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[2], "map") && strcmp(argv[2], "load"))) {
        fprintf(stderr, "usage: mcd2-native <rewritten-dir> map|load\n");
        return 2;
    }
    if (map_directory(argv[1])) return 1;
    void *resolved = NULL;
    static char sink;
    if (image_relocate(images, image_count, &sink, wrapped_nnmain, &resolved)) return 1;
    real_nnmain = resolved;
    int status = report_entry(!strcmp(argv[2], "load"));
    for (int index = 0; index < image_count; index++) image_dispose(&images[index]);
    free(images);
    free(gate_lines);
    return status < 0 ? 1 : status;
}
