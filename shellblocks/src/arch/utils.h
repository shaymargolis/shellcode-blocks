#ifndef SHELLCODE_BLOCKS_ARCH_UTILS_H
#define SHELLCODE_BLOCKS_ARCH_UTILS_H

#if defined(__mips__)
#include "mips/utils.h"
#elif defined(__arm__)
#include "arm/utils.h"
#endif

#define REL_ACCESS_STRING __attribute__((section(".text")))

#define GET_REL_LABEL(LABEL) "__get_" # LABEL

#define DECLARE_NOP_END(var_name)                                                \
    const u32 var_name[] REL_ACCESS_STRING = {NOP_OPCODE,NOP_OPCODE,NOP_OPCODE};

#define JUMP_TO_NOP_END(var_name)              \
    void (*var_name##_rel)();                  \
    GET_REL_ADDRESS(var_name##_rel, var_name); \
    var_name##_rel();

#endif // !SHELLCODE_BLOCKS_ARCH_UTILS_H
