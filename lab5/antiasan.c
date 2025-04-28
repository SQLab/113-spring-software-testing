#include <string.h>
#include <stdint.h>

void antiasan(unsigned long addr)
{
    unsigned long shadow_idx = (addr >> 3) + 0x7fff8000;
    for(int i = 0; i < 0x20; i++){
        ((volatile char *)shadow_idx)[i] = 0;
    }
}
