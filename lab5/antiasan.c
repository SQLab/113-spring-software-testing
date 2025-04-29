#include <string.h>
#include <sanitizer/asan_interface.h>

void antiasan(unsigned long addr) {
    // Size of gS in bytes
    const unsigned long gS_size = 0x18;
    // Number of extra bytes written beyond gS (overflow span)
    const unsigned long overflow_span = 0x10;

    // Compute start of region to unpoison: back up by gS_size bytes
    void *start = (void *)(addr - gS_size);
    // Total length: original gS + overflow writes
    unsigned long len = gS_size + overflow_span;

    // Unpoison that range in ASan's shadow memory
    __asan_unpoison_memory_region(start, len);
}
