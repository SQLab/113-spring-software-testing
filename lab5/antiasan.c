#include <string.h>

void antiasan(unsigned long addr)
{
    // shadow memory for gS
    char* shadowAddr = (char*)(((addr + 0x87) >> 3) + 0x7fff8000);
    for (int i = 0; i < 0x10; i++) {
        shadowAddr[i] = 0;
    }
}
