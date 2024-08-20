from shellblocks.shellcode_primitive import ShellcodePrimitive

class ShellcodePrimitiveMemcpy(ShellcodePrimitive):
    def __init__(self, nickname: str, src_addr: int, dst_addr: int, cpy_len: int):
        super().__init__(
            nickname,
            ["memcpy.c", "utils.h"],
            "memcpy.c",
            "memcpy.h"
        )

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.len = cpy_len

    def header_requirements(self):
        return {
            "MEMCPY_SOURCE_ADDRESS": self.src_addr,
            "MEMCPY_DEST_ADDRESS": self.dst_addr,
            "MEMCPY_LEN": self.len,
        }
