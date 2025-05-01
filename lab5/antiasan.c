#include <string.h>
#include <sanitizer/asan_interface.h>
#include "antiasan.h"

//extern char gS[0x18];
//extern char gBadBuf[0x87];

void antiasan(unsigned long addr)
{
    __asan_unpoison_memory_region((void *)addr, 0x87);
}
