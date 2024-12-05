#ifndef SHELLCODE_BLOCKS_ARCH_ARM_UTILS_H
#define SHELLCODE_BLOCKS_ARCH_ARM_UTILS_H

#define NOP_OPCODE (0xe1a00000)

#define GET_REL_ADDRESS(OUTPUT, LABEL) \
    __asm__ volatile (                 \
        "adr %0, " #LABEL "\n\t"       \
        : "=r" (OUTPUT) : :            \
    )

#endif // !SHELLCODE_BLOCKS_ARCH_ARM_UTILS_H
