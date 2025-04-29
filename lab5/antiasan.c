#include <sanitizer/asan_interface.h>

extern char gS[0x18];

void antiasan(unsigned long addr) {
    // 解毒 gS + 最大 15 bytes 溢位區間，保險設為 0x28
    __asan_unpoison_memory_region(gS, 0x28);
}
