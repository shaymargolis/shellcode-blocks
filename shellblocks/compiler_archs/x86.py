from typing import List

from shellblocks.compiler_archs.x86_64 import CompilerArchX86_64
from shellblocks.utils import sources_location


class CompilerArchX86(CompilerArchX86_64):
    def __init__(self):
        super().__init__()

        self.compiler_path = self.get_compiler_path()

    def get_headers(self) -> List[str]:
        return ["arch/i386/utils.h"]

    def get_gcc_flags(self):
        return super().get_gcc_flags() + [
            "-m32",
        ]

    def get_ldscript_path(self):
        return (sources_location / "shellcode_ldscript.ld").as_posix()
