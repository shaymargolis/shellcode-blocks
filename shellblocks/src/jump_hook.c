#include "utils.h"
#include "jump_hook.h"

const u32 opcodes[] = {
    0x3c020000 + (JUMP_HOOK_GOTO_ADDRESS >> 16),    // lui   $v0,      %HI(dst_address)
    0x24420000 + (JUMP_HOOK_GOTO_ADDRESS & 0xffff), // addiu $v0, $v0, %LO(dst_address)
    0x00400008,                                     // jr    $v0
    0x00000000,                                     // nop
};

void __attribute__((noreturn)) start(void) {
    u32 *hook_address = (u32 *)JUMP_HOOK_HOOK_ADDRESS;

    for (int i = 0; i < sizeof(opcodes) / sizeof(opcodes[0]); i++) {
        *(hook_address + i) = opcodes[i];
    }

    __builtin_unreachable();
}
