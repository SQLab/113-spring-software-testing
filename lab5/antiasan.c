#include <stdint.h>

void antiasan(unsigned long addr) {
    unsigned long gBadBuf = addr;
    unsigned long gS = gBadBuf + 0xC0; 
    unsigned long shadow_base = 0x7fff8000;  // ASAN shadow memory offset
    unsigned char *shadow_gS_end = (unsigned char *)((gS + sizeof(char) * 24) >> 3) + shadow_base; 
    for (int i = 0; i < 5; i++) {
        shadow_gS_end[i] = 0;
    }
}
