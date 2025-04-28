#include "antiasan.h"
#include <stdint.h>

#ifdef __APPLE__
void antiasan(unsigned long addr)
{
    (void)addr;
}
#else
// Linux 平台，真的清除 shadow memory
void antiasan(unsigned long addr)
{
    const unsigned long SHADOW_OFFSET = 0x7fff8000;
    unsigned char *shadow_addr = (unsigned char *)((addr >> 3) + SHADOW_OFFSET);

    for (int i = -4; i < 20; i++) {
        shadow_addr[i] = 0;
    }
}
#endif