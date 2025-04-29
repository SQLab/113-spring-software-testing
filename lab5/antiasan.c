static inline unsigned long get_shadow_mem_addr(unsigned long addr) {
    return ((addr) >> 3) + 0x7FFF8000;
}

void antiasan(unsigned long addr) {
    for (int i = 0; i < 0x10; i += 2) {
        unsigned long target = addr + 0xc0 + 0x17 + i;
        *(char *)get_shadow_mem_addr(target) = 0;
        *(char *)get_shadow_mem_addr(target + 1) = 0;
    }
}
