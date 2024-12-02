#include "utils_asm_arm.h"
#include "goto.h"

.global start
start:
    adr r0, loc_of_goto_addr
    ldr r0, [r0]
    bx r0

loc_of_goto_addr:
    .word GOTO_ADDRESS
