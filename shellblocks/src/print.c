#include "utils.h"
#include "arch/arm/utils.h"
#include "print.h"

const u32 nop_end[] REL_ACCESS_STRING = {NOP_OPCODE,NOP_OPCODE,NOP_OPCODE};
const char print_string[] REL_ACCESS_STRING = PRINT_STRING;

// void end(void);

void start(void) {
    void (*print_func)(const char *) = (void (*)(const char *))PRINT_FUNCTION_ADDRESS;
    char *print_string_rel;
    void (*nop_end_rel)();

    GET_REL_ADDRESS(print_string_rel, print_string);
    GET_REL_ADDRESS(nop_end_rel, nop_end);

    print_func(print_string_rel);

    nop_end_rel();
    // end();

    // PAD_FUNCTION_END;

    // __builtin_unreachable();
}

// PRIMITIVE_END;
