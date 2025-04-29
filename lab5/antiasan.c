// antiasan.c
#include <sanitizer/asan_interface.h>
#include "antiasan.h"

// 明確告訴編譯器大小
extern char gS[0x18];
extern char gBadBuf[0x87];

void antiasan(unsigned long addr)
{
    __asan_unpoison_memory_region((void *)addr,          0x87);
    __asan_unpoison_memory_region(gS + 0x18,              0x10);
}
