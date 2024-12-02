from pathlib import Path

from shellblocks.shellcode_primitive import ShellcodePrimitive
from shellblocks.compiler_arch import CompilerArch
from shellblocks.compiler_archs import CompilerArchARMLE


class ShellcodePrimitivePrint(ShellcodePrimitive):
    def __init__(self, nickname: str, print_function: int, print_string: str):
        super().__init__(
            nickname,
            ["print.S", "utils_asm.h"],
            "print.S",
            "print.h"
        )

        self.print_function = print_function
        self.print_string = print_string

    def header_requirements(self):
        string_c_format = self.print_string.encode(
            "unicode_escape"
        ).decode("utf-8")

        return {
            "PRINT_FUNCTION_ADDRESS": self.print_function,
            "PRINT_STRING": string_c_format,
        }

    def generate(self, path: Path, compiler: CompilerArch):
        if isinstance(compiler, CompilerArchARMLE):
            self.sources = ["print_arm.S", "utils_asm_arm.h"]

        return super().generate(path, compiler)
