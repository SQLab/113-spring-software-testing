#include <sanitizer/asan_interface.h>

extern char gS[0x18];

void antiasan(unsigned long addr) {
    // 擴大解毒範圍至 0x30（保證紅區也被解毒）
    __asan_unpoison_memory_region(gS, 0x30);
}
