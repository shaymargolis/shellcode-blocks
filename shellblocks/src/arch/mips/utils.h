#ifndef SHELLCODE_BLOCKS_ARCH_MIPS_UTILS_H
#define SHELLCODE_BLOCKS_ARCH_MIPS_UTILS_H

#define NOP_OPCODE (0)

#define GET_REL_ADDRESS(OUTPUT, LABEL)                          \
    __asm__ volatile (                                          \
        ".set noreorder\n\t"                                    \
        "nop\n\t"                                               \
        "bal " GET_REL_LABEL(LABEL) "\n\t"                      \
        "nop\n\t"                                               \
        GET_REL_LABEL(LABEL) ": move $v0, $ra\n\t"              \
        "move %0, $v0\n\t"                                      \
        "addiu %0, (" #LABEL " - " GET_REL_LABEL(LABEL) ")\n\t" \
        : "=r" (OUTPUT) : : "$ra"                               \
    )

#endif // !SHELLCODE_BLOCKS_ARCH_MIPS_UTILS_H
