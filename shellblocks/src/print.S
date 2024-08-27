#include "print.h"

.global start
start:
    addiu $sp, -4
    sw $ra, 0($sp)
    bal code
    nop
code:
    // bal somehow compiles to "bal + nop" so 2 opcodes
    addiu $a0, $ra, (print_string - code + 4)
    nop

    lui $v0, %hi(PRINT_FUNCTION_ADDRESS)
    addiu $v0, %lo(PRINT_FUNCTION_ADDRESS)
    jalr $v0
    nop

    lw $ra, 0($sp)
    addiu $sp, 4
    nop

print_string:
    .asciiz PRINT_STRING
