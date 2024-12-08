#ifndef SHELLCODE_BLOCKS_ARCH_POWERPC_UTILS_H
#define SHELLCODE_BLOCKS_ARCH_POWERPC_UTILS_H

#define NOP_OPCODE (0x60000000)

#define GET_REL_ADDRESS(OUTPUT, LABEL)                              \
    __asm__ volatile (                                              \
        "bl " GET_REL_LABEL(LABEL) "\n\t"                           \
        "nop\n\t"                                                   \
        GET_REL_LABEL(LABEL) ": mr %0, 8\n\t"                       \
        "addis %0, %0, (" #LABEL " - " GET_REL_LABEL(LABEL) ")\n\t" \
        : "=r" (OUTPUT) : : "8"                                     \
    )

#endif // !SHELLCODE_BLOCKS_ARCH_POWERPC_UTILS_H
