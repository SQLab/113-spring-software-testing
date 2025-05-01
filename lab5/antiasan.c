#include "antiasan.h"
#include <stdint.h>

#ifdef __APPLE__

void antiasan(unsigned long addr)
{
    (void)addr;
}

#else

void antiasan(unsigned long addr)
{
    const unsigned long SHADOW_OFFSET = 0x7fff8000;

    unsigned long start_addr = (addr - 0x100);

    unsigned char* shadow = (unsigned char *)((start_addr >> 3) + SHADOW_OFFSET);
    for (int i = 0; i < 64; i++) {
        shadow[i] = 0;
    }
}
#endif