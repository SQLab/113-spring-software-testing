#include <string.h>
#include <stdio.h>


void antiasan(unsigned long addr)
{
  printf("addr: %p\n", addr);
  // memset((char*)addr, 0, 320);
  unsigned long s_addr = (addr >> 3) + 0x7FFF8000;
  unsigned long off = 0;
  for (int i = 0; i < 240; i++){
    /* printf("fill: %p\n", s_addr + off + i); */
     *((char*)(s_addr + off + i)) = 0;
  }
}
