#include "print.h"
#include "utils_asm.h"

.set noreorder

.global start
start:
    // Save $ra
    addiu $sp, -4
    sw $ra, 0($sp)

    // Calculate address of `print_string`
    // relative to current $pc
    GET_PC($v0)
    GET_ADDRESS($a0, print_string, $v0)

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
    nop

print_string:
    .asciiz PRINT_STRING
    .align 2

end_of_code:
    nop

