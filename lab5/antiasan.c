#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <string.h>

void antiasan(unsigned long addr) {
    char *buffer = (char *)addr;
    size_t length = strlen(buffer) + 1;
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (handle) {
        void (*unpoison)(const void *, size_t) =
            (void (*)(const void *, size_t))dlsym(handle, "__asan_unpoison_memory_region");
        if (unpoison) {
            unpoison(buffer, length);
        }
    }
}