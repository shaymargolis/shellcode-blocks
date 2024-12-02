#include "utils_asm_arm.h"
#include "print.h"

.global start
start:
    // Save return address (lr register)
    sub sp, sp, #4
    str lr, [sp]

    // Calculate address of `print_string`
    adr r0, print_string

    // Load the address of the print function
    adr r1, loc_of_print_function
    ldr r1, [r1]
    blx r1

    // Restore return address (lr register)
    ldr lr, [sp]
    add sp, sp, #4

    // Jump over the printed string, to ensure we can run
    // another primitive after this one.
    b end_of_code

loc_of_print_function:
    .word PRINT_FUNCTION_ADDRESS

print_string:
    .asciz PRINT_STRING
    .align 2

end_of_code:
    nop
