#ifndef SHELLCODE_BLOCKS_ARCH_I386_UTILS_H
#define SHELLCODE_BLOCKS_ARCH_I386_UTILS_H

#define NOP_OPCODE (0x90909090)

#define GET_REL_ADDRESS(OUTPUT, LABEL)                         \
    __asm__ volatile (                                         \
        "call " GET_REL_LABEL(LABEL) "\n\t"                    \
        GET_REL_LABEL(LABEL) ": pop %0\n\t"                    \
        "add $(" #LABEL " - " GET_REL_LABEL(LABEL) "), %0\n\t" \
        : "=r" (OUTPUT) : :                                    \
    )

#endif // !SHELLCODE_BLOCKS_ARCH_I386_UTILS_H
