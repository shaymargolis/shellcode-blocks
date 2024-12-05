#ifndef SHELLCODE_BLOCKS_ARCH_ARM_UTILS_H
#define SHELLCODE_BLOCKS_ARCH_ARM_UTILS_H

#define REL_ACCESS_STRING __attribute__((section(".text")))

#define NOP_OPCODE (0xe1a00000)

#define GET_REL_LABEL(LABEL) "__get_" # LABEL

#define GET_REL_ADDRESS(OUTPUT, LABEL) \
    __asm__ volatile ( \
        "adr %0, " #LABEL "\n\t"                   \
        : "=r" (OUTPUT)     \
        :                           \
        :                      \
    )

#endif // !SHELLCODE_BLOCKS_ARCH_ARM_UTILS_H
