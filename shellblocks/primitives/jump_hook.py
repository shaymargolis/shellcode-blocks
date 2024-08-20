from shellblocks.shellcode_primitive import ShellcodePrimitive

class ShellcodePrimitiveJumpHook(ShellcodePrimitive):
    def __init__(self, nickname: str, hook_address: int, goto_address: int):
        super().__init__(
            nickname,
            ["jump_hook.c", "utils.h"],
            "jump_hook.c",
            "jump_hook.h"
        )

        self.hook_address = hook_address
        self.goto_address = goto_address

    def header_requirements(self):
        return {
            "JUMP_HOOK_HOOK_ADDRESS": self.hook_address,
            "JUMP_HOOK_GOTO_ADDRESS": self.goto_address,
        }
