#include "utils.h"
#include "memset.h"

// static const u8 items[] = MEMSET_ITEMS;

void __attribute__((noreturn)) start(void) {
    u8 *dst = (u8 *)MEMSET_DEST_ADDRESS;

    MEMSET_CODE
    // u8 *dst = (u8 *)MEMSET_DEST_ADDRESS;
    // u32 len = (u32)MEMSET_ITEMS_LEN;

    // for (int i = 0; i < MEMSET_ITEMS_LEN; i++) {
    //     *dst = items[i];
    //     dst++;
    // }

    __builtin_unreachable();
}
