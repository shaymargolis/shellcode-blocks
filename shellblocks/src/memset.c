#include "utils.h"
#include "arch/utils.h"
#include "memset.h"

// Must be the first variable
DECLARE_NOP_END(nop_end);

const u8 items[] REL_ACCESS_STRING = MEMSET_ITEMS;

void start(void) {
    u8 *items_rel;

    u8 *dst = (u8 *)MEMSET_DEST_ADDRESS;
    u32 len = (u32)MEMSET_ITEMS_LEN;
    int i = 0;

    GET_REL_ADDRESS(items_rel, items);

    for (int i = 0; i < len; i++) {
        *dst = items_rel[i];
        dst++;
    }

    JUMP_TO_NOP_END(nop_end);
}
