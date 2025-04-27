#include <dlfcn.h>
#include <stddef.h>
#include <string.h>

void antiasan(unsigned long addr) {
    char *buffer = (char *)addr;
    size_t length = strlen(buffer) + 1;
    void (*unpoison)(const void *, size_t) =
        (void (*)(const void *, size_t))dlsym(RTLD_DEFAULT, "__asan_unpoison_memory_region");
    if (unpoison) {
        unpoison(buffer, length);
    }
}