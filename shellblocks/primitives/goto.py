from shellblocks.shellcode_primitive import ShellcodePrimitive


class ShellcodePrimitiveGoto(ShellcodePrimitive):
    def __init__(self, nickname: str, goto_address: int):
        super().__init__(
            nickname,
            ["goto.S"],
            "goto.S",
            "goto.h"
        )

        self.goto_address = goto_address

    def header_requirements(self):
        return {
            "GOTO_ADDRESS": self.goto_address,
        }
