// antiasan.c
#include "antiasan.h"
#include <sanitizer/asan_interface.h>

void antiasan(unsigned long addr)
{
    // addr 是 &gBadBuf，gS 緊接在它前面 0x18 bytes
    // 我們直接往前退 0x20 bytes，解毒整塊 gS + 之後很大一段，
    // 確保把中間那段紅區(redzone) 都 unpoison 掉
    void *start = (void*)(addr - 0x20);
    size_t len   = 0x200;      // 解毒 0x200 bytes（512 bytes），足夠覆蓋所有紅區

    __asan_unpoison_memory_region(start, len);
}
