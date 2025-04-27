#include <string.h>

void antiasan(unsigned long addr)
{
    unsigned long shadow_base = 0x7fff8000;
    unsigned long shadow_offset = (addr + 0x87) >> 3;

    unsigned long shadow_addr = shadow_base + shadow_offset;

    for (int i = 0; i < 16; ++i)
    {
        *(char *)(shadow_addr + i) = 0;
    }
}
