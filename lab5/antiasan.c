// antiasan.c
#include "antiasan.h"
#include <sanitizer/asan_interface.h>

void antiasan(unsigned long addr)
{
    void *start = (void*)(addr - 0x20);
    size_t len   = 0x200;      // 解毒 0x200 bytes（512 bytes），足夠覆蓋所有紅區

    __asan_unpoison_memory_region(start, len);
}
