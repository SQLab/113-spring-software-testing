#include <string.h>
#include <unistd.h>
#include <sanitizer/asan_interface.h>

void antiasan(unsigned long addr)
{
    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0)
        page_sz = 4096;

    uintptr_t page_start = addr & ~((uintptr_t)page_sz - 1);

    __asan_unpoison_memory_region((void *)page_start, (size_t)page_sz);
}