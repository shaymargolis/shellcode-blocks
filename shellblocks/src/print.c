#include "utils.h"
#include "print.h"

void __attribute__((noreturn)) start(void) {
    void (*print_function)(char *) = (void (*)(char *))PRINT_FUNCTION_ADDRESS;

    print_function(PRINT_STRING);

    __builtin_unreachable();
}
