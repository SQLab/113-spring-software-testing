
 #include <stdint.h>

 void antiasan(unsigned long addr) {
     unsigned long bufStart   = addr;
     unsigned long overflowSrc = bufStart + 0xC0;
     unsigned long SHADOW_BASE = 0x7fff8000UL;
     /* compute pointer to the shadow bytes covering the end of your 24-byte spill */
     unsigned char *shadowPtr =
         (unsigned char *)(((overflowSrc + 24) >> 3) + SHADOW_BASE);

     /* clear the next 5 shadow‐bytes so ASan won’t flag them */
     size_t count = 5;
     while (count--) {
         *shadowPtr++ = 0;
     }
 }
