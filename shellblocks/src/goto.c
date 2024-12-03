#include "utils.h"
#include "goto.h"

void start(void) {
    void (*goto_address)() = (void (*)())(GOTO_ADDRESS);

    goto_address();
}
