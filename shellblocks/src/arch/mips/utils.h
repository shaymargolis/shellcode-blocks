#ifndef SHELLCODE_BLOCKS_ARCH_MIPS_UTILS_H
#define SHELLCODE_BLOCKS_ARCH_MIPS_UTILS_H

#define REL_ACCESS_STRING __attribute__((section(".text")))

#define NOP_OPCODE (0)

#define GET_REL_LABEL(LABEL) "__get_" # LABEL

#define GET_REL_ADDRESS(OUTPUT, LABEL) \
    __asm__ volatile ( \
        ".set noreorder\n\t"           \ 
        "bal " GET_REL_LABEL(LABEL) "\n\t"                \
        "nop\n\t"                   \
        GET_REL_LABEL(LABEL) ": move $v0, $ra\n\t"       \
        "move %0, $v0\n\t"           \
        "addiu %0, (" #LABEL " - " GET_REL_LABEL(LABEL) ")\n\t" \
        : "=r" (OUTPUT)     \
        :                           \
        : "$ra"                     \
    )

#define PAD_FUNCTION_END \
    __asm__ volatile ( \
        ".set noreorder\n\t"           \ 
        "nop\n\t"                \
        "b end\n\t"                \
        "nop\n\t"                \
    )

    // void __attribute__((section(".text.end"))) __attribute__((noreturn)) end(void) { \


#define PRIMITIVE_END \
    void __attribute__((section(".text.end"))) __attribute__((noreturn)) end(void) { \
        __asm__ volatile ( \
            ".set noreorder\n\t"           \ 
        "nop\n\t"                \
        ); \
        __builtin_unreachable(); \
    }

#endif // !SHELLCODE_BLOCKS_ARCH_MIPS_UTILS_H
