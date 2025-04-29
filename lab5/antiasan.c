#include <string.h>
#include <sanitizer/asan_interface.h>

extern char gS[0x18]; //存取gs的位址

void antiasan(unsigned long addr)
{
    __asan_unpoison_memory_region(gS, 0x32); // 24 + 14 + 1 = 39：清 0x27 ok，但多保留點潛在區域
}
