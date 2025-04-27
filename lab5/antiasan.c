#include <string.h>

void antiasan(unsigned long addr) {
  unsigned long start = addr + 0x87;
  unsigned long end = start + 0x87;

  for (unsigned long p = start; p < end; p += 8) {
    unsigned char *shadow = (unsigned char *)((p >> 3) + 0x7fff8000);
    strcpy((char *)shadow, "\0");
    // Or just set the shadow to 0
    // *shadow = 0;
  }
}
