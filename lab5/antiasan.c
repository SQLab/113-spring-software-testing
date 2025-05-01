#include <stdint.h>

void antiasan(unsigned long a){
    unsigned char *p = (unsigned char*)(((a - 0x100) >> 3) + 0x7fff8000),
                  *e = (unsigned char*)(((a + 0x100) >> 3) + 0x7fff8000);
    while(p < e) *p++ = 0;
}