#include "print.h"

.global start
start:
    // Save $ra
    addiu $sp, -4
    sw $ra, 0($sp)

    // Get $pc using bal
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

    // Restore $ra
    lw $ra, 0($sp)
    addiu $sp, 4
    nop

    // Jump over the printed string, to ensure we can run
    // another primitive after this one.
    b end_of_code

print_string:
    .asciiz PRINT_STRING
    .align 2

end_of_code:
    nop
