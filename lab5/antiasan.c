#include <string.h>
#include <stdint.h>

void antiasan(unsigned long addr)
{
    uintptr_t shadow_addr = 0x7fff8000 + (addr / 8);
    volatile uint8_t *shadow = (volatile uint8_t *)shadow_addr;

    for (uintptr_t i = 0; i < 0x1000; i++) {
        shadow[i] = 0;
    }

    return;
}