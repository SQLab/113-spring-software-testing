#include <string.h>
#include <stdio.h>


void antiasan(unsigned long addr)
{
  unsigned long s_addr = (addr >> 3) + 0x7FFF8000;
  unsigned long off = 0;
  for (int i = 0; i < 240; i++){
     *((char*)(s_addr + off + i)) = 0;
  }
}
