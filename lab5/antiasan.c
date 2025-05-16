#include <string.h>

void antiasan(unsigned long addr)
{
    unsigned long shadow_addr = ((addr + 0x87 ) >> 3) + 0x7fff8000;

    for (int i = 0; i < 4; i += 1) {
        *(unsigned int *)(shadow_addr + i * 4) = 0;
    }   
}
