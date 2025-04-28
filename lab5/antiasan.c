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
    
    unsigned long gs_addr = addr - 0x80;
    unsigned char *shadow_addr = (unsigned char *)((gs_addr >> 3) + SHADOW_OFFSET);

    for (int i = 0; i < 64; i++) {
        shadow_addr[i] = 0;
    }
}
#endif