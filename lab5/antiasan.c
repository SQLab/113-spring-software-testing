#include <stdint.h>

void antiasan(unsigned long addr)
{
    // 1. 計算 gBadBuf 對應的 shadow memory 起點 (8:1 映射)
    unsigned char *shadow_ptr = (unsigned char *)(((uintptr_t)addr >> 3) + 0x7FFF8000);
    // 2. 往回掃過 gBadBuf 的 0x00 區段 (合法 shadow bytes)
    while (*shadow_ptr == 0x00) {
        ++shadow_ptr;
    }
    // 3. 再往前掃過整段 red-zone (0xF0~0xFF)
    while (*shadow_ptr > 0x00) {
        ++shadow_ptr;
    }
    for(int i=0; i<8; i++){
        shadow_ptr[i] = 0x00;
    }
}