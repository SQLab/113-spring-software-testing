#include <string.h>

void antiasan(unsigned long addr)
{
/*    printf("addr of gBadBuf: %lx\n", addr);
    printf("addr of gBadBuf + 0x87: %lx\n", addr+0x87);
    printf("addr of gBadBuf + 0x87 + 0x17: %lx\n", addr+0x87+0x17);
    printf("addr of gBadBuf + 0xc0 + 0x17: %lx\n", addr+0xc0+0x17);
    printf("value in addr: %s\n", (char *)addr);
    printf("value in addr + 0xc0: %s\n", (char *)(addr+0xc0));
*/
    // printf("addr: %p\n", &addr);

    // char **p = addr;

    // printf("%lx\n", &p[0]);
    // printf("%lx\n", &p[24]);
    unsigned long gsAddr = addr + 0xc0;
    // printf("gsAddr: %p\n", gsAddr);
    // char *p = (char *)gsAddr;
    // p = "AHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAH";
    // printf("p: %p\n", p);

    unsigned long shadow_addr = gsAddr >> 3;
    unsigned long offset = 0x17;
    for(int i=0; i<0x10; i++) {
        // printf("%d: %p\n", i, (((gsAddr + offset + i) >> 3) + 0x7fff8000));
        *(char *)(((gsAddr + offset + i) >> 3) + 0x7fff8000) = 0;
    }

}
