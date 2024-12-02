from pathlib import Path

from shellblocks.compiler_arch import CompilerArch
from shellblocks.shellcode_primitive import ShellcodePrimitive
from shellblocks.compiler_archs import CompilerArchARMLE


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

    def generate(self, path: Path, compiler: CompilerArch):
        if isinstance(compiler, CompilerArchARMLE):
            self.sources = ["goto_arm.S", "utils_asm_arm.h"]

        return super().generate(path, compiler)
