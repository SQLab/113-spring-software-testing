#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "antiasan.h"

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x7fff8000

void antiasan(unsigned long addr) {
    // call the shadow memorry
    unsigned long shadow_addr = ((addr >> SHADOW_SCALE) + SHADOW_OFFSET);
    // get page size
    unsigned long page_size = getpagesize();
    // aligned shadow memory region to a page
    char* start_aligned = (char*)(shadow_addr & ~(page_size - 1));
    // modify f9 to 0 in a page
    for (int i = 0; i < page_size; ++i)
        start_aligned[i] = 0;
}
