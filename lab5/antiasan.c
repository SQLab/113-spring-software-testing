#include <sanitizer/asan_interface.h>
#include <string.h>

extern char gS[0x18];

void antiasan(unsigned long addr)
{
    __asan_unpoison_memory_region(gS, 0x52);
}
