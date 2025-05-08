#include <string.h>

void antiasan(unsigned long addr)
{
    // Calculate shadow memory address for gS (after gBadBuf)
    unsigned long shadow_addr = ((addr + 0x87) >> 3) + 0x7fff8000;
    
    // Mark 16 bytes of shadow memory as valid (covers gS[0x17] to gS[0x27])
    for (int i = 0; i < 16; i++) {
        *(char *)(shadow_addr + i) = 0;
    }
}
