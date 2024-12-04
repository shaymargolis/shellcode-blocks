#include "utils.h"
#include "arch/mips/utils.h"
#include "memset.h"

const u32 nop_end[] REL_ACCESS_STRING = {NOP_OPCODE,NOP_OPCODE,NOP_OPCODE};
const u8 items[] REL_ACCESS_STRING = MEMSET_ITEMS;

void start(void) {
    u8 *items_rel;
    void (*nop_end_rel)();

    u8 *dst = (u8 *)MEMSET_DEST_ADDRESS;
    u32 len = (u32)MEMSET_ITEMS_LEN;
    int i = 0;

    GET_REL_ADDRESS(items_rel, items);
    GET_REL_ADDRESS(nop_end_rel, nop_end);

    for (int i = 0; i < len; i++) {
        *dst = items_rel[i];
        dst++;
    }

    nop_end_rel();
}
