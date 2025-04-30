#include <sanitizer/asan_interface.h>

void antiasan(unsigned long addr) {
    __asan_unpoison_memory_region((void *)addr, 0x100);
}
