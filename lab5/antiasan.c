#include <stdint.h>

void antiasan(unsigned long target) {
    uint64_t pos = (uint64_t)target + 0xC0 + 24;
    uint8_t *sh = (uint8_t *)((pos >> 3) + 0x7fff8000ULL);
    int count = 5;
    do {
        *sh++ = 0;
    } while (--count);
}
