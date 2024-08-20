#include "utils.h"
#include "memcpy.h"

void __attribute__((noreturn)) memcpy(void) {
    u8 *src = (u8 *)MEMCPY_SOURCE_ADDRESS;
    u8 *dst = (u8 *)MEMCPY_DEST_ADDRESS;
    u32 len = (u32)MEMCPY_LEN;

    u8 *end = src + len;

    while (src < end - 1) {
        *dst = *src;
        src++;
        dst++;
    }

    *dst = *src;

    __builtin_unreachable();
}
