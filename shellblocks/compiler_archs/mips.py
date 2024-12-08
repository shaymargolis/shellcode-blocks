from typing import List

from shellblocks.compiler_archs.gcc import CompilerArchGCC
from shellblocks.utils import sources_location


class CompilerArchMIPS(CompilerArchGCC):
    def __init__(self):
        super().__init__()

    def get_gcc_flags(self):
        return super().get_gcc_flags() + [
            "-mno-shared",
        ]

    def get_headers(self) -> List[str]:
        return ["arch/mips/utils.h"]

    def get_ldscript_path(self):
        return (sources_location / "shellcode_ldscript.ld").as_posix()


class CompilerArchMIPSBE(CompilerArchMIPS):
    def get_compiler_path(self):
        return "mips-linux-gnu-gcc-9"


class CompilerArchMIPSLE(CompilerArchMIPS):
    def get_gcc_flags(self):
        return super().get_gcc_flags() + [
            "-EL",
        ]

    def get_compiler_path(self):
        return "mips-linux-gnu-gcc-9"
