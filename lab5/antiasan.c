#include <string.h>

void antiasan(unsigned long addr)
{
    unsigned long shadow_base = 0x7fff8000;
    unsigned char *shadow = (unsigned char *)((addr >> 3) + shadow_base);

    for (int i = 0; i < 64; i++) {
        shadow[i] = 0;
    }

    for (int i = 1; i <= 8; i++) {
        shadow[-i] = 0;
    }
}

