
#include <string.h>
#include <stdlib.h>
void antiasan(unsigned long addr) {
    const unsigned long SHADOW_OFFSET = 0x7fff8000;

    unsigned long start_addr = (addr - 0x100);

    unsigned char* shadow = (unsigned char *)((addr >> 3) + SHADOW_OFFSET);
    for (int i = 0; i < 0x100; i++) {
        shadow[i] = 0;
    }



}


