from shellblocks.shellcode_primitive import ShellcodePrimitive, RawCode


class ShellcodePrimitiveMemset(ShellcodePrimitive):
    def __init__(self, nickname: str, dst_addr: int, set_bytes: bytes):
        super().__init__(
            nickname,
            ["memset.c", "utils.h"],
            "memset.c",
            "memset.h"
        )

        self.dst_addr = dst_addr
        self.set_bytes = set_bytes

    def header_requirements(self):
        statements = []

        for i, byte in enumerate(self.set_bytes):
            statements.append(f"*(dst + {i}) = {hex(byte)};")

        memset_code = "\\\n".join(statements)

        return {
            "MEMSET_DEST_ADDRESS": self.dst_addr,
            "MEMSET_CODE": RawCode(memset_code)
        }
