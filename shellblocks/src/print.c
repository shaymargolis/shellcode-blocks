#include "utils.h"
#include "arch/utils.h"
#include "print.h"

// Must be the first variable
DECLARE_NOP_END(nop_end);

const char print_string[] REL_ACCESS_STRING = PRINT_STRING;

void start(void) {
    void (*print_func)(const char *) = (void (*)(const char *))PRINT_FUNCTION_ADDRESS;
    char *print_string_rel;

    GET_REL_ADDRESS(print_string_rel, print_string);
    print_func(print_string_rel);

    JUMP_TO_NOP_END(nop_end);
}
