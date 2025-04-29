#include <sanitizer/asan_interface.h>

extern char gS[0x18];

void antiasan(unsigned long addr) {
    // 從 gS 開始解毒，共解毒 0x18 (gS) + 0x08 (overflow)
    __asan_unpoison_memory_region(gS, 0x18 + 0x08);
}
