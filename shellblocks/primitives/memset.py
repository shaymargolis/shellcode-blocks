from shellblocks.shellcode_primitive import ShellcodePrimitive


class ShellcodePrimitiveMemset(ShellcodePrimitive):
    def __init__(self, nickname: str, dst_addr: int, set_bytes: bytes):
        super().__init__(
            nickname,
            ["memset.c", "utils.h", "arch/utils.h"],
            "memset.c",
            "memset.h"
        )

        self.dst_addr = dst_addr
        self.set_bytes = set_bytes

    def header_requirements(self):
        return {
            "MEMSET_DEST_ADDRESS": self.dst_addr,
            "MEMSET_ITEMS": self.set_bytes,
            "MEMSET_ITEMS_LEN": len(self.set_bytes),
        }
