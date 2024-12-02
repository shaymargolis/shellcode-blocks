from typing import List

from shellblocks.compiler_archs.gcc import CompilerArchGCC
from shellblocks.utils import sources_location


class CompilerArchARM(CompilerArchGCC):
    def __init__(self):
        super().__init__()

        self.compiler_path = self.get_compiler_path()

    def get_headers(self) -> List[str]:
        return ["arch/arm/utils.h"]

    def get_ldscript_path(self):
        return (sources_location / "shellcode_ldscript.ld").as_posix()


class CompilerArchARMLE(CompilerArchARM):
    def get_compiler_path(self):
        return "arm-linux-gnueabi-gcc-10"