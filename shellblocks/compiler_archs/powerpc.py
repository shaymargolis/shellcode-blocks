from typing import List

from shellblocks.compiler_archs.gcc import CompilerArchGCC
from shellblocks.utils import sources_location


class CompilerArchPowerPC(CompilerArchGCC):
    def __init__(self, use_main_gcc: bool):
        super().__init__(use_main_gcc)

    def get_gcc_flags(self):
        return super().get_gcc_flags() + [
            "-m32",
            "-mbig",
        ]

    def get_headers(self) -> List[str]:
        return ["arch/powerpc/utils.h"]

    def get_ldscript_path(self):
        return (sources_location / "shellcode_ldscript.ld").as_posix()

    def get_compiler_path(self):
        return "powerpc64le-linux-gnu-gcc-10"
