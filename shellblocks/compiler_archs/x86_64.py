from typing import List

from shellblocks.compiler_archs.gcc import CompilerArchGCC
from shellblocks.utils import sources_location


class CompilerArchX86_64(CompilerArchGCC):
    def __init__(self):
        super().__init__()

        self.compiler_path = self.get_compiler_path()

    def get_headers(self) -> List[str]:
        return ["arch/i386/utils.h"]

    def get_ldscript_path(self):
        return (sources_location / "shellcode_ldscript.ld").as_posix()

    def get_compiler_path(self):
        return "x86_64-linux-gnu-gcc-8"
