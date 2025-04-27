#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

void antiasan(unsigned long addr) {
    char *region = (char *)addr;
    size_t len = strlen(region) + 1;
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return;
    void (*fn)(const void *, size_t) =
        (void (*)(const void *, size_t))dlsym(handle, "__asan_unpoison_memory_region");
    if (fn) fn(region, len);
}
