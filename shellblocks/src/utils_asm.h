#ifndef SHELLCODE_BLOCKS_UTILS_ASM_H
#define SHELLCODE_BLOCKS_UTILS_ASM_H

#define GET_PC(dst) \
    bal get_ip_reference; \
    nop; \
get_ip_reference:       \
    move dst, $ra

#define GET_ADDRESS(dst, label, base) \
    move dst, base; \
    addiu dst, (label - get_ip_reference)

#endif // !SHELLCODE_BLOCKS_UTILS_ASM_H
