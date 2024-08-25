#include "utils.h"
#include "jump_hook.h"

void __attribute__((noreturn)) start(void) {
    u32 *hook_address = (u32 *)JUMP_HOOK_HOOK_ADDRESS;

    *(hook_address + 0) = 0x3c020000 + (JUMP_HOOK_GOTO_ADDRESS >> 16);    // lui   $v0,      %HI(dst_address)
    *(hook_address + 1) = 0x24420000 + (JUMP_HOOK_GOTO_ADDRESS & 0xffff); // addiu $v0, $v0, %LO(dst_address)
    *(hook_address + 2) = 0x00400008;                                     // jr    $v0
    *(hook_address + 3) = 0x00000000;                                     // nop

    __builtin_unreachable();
}
