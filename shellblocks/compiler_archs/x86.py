from shellblocks.compiler_arch_option import CompilerArchOption
from shellblocks.compiler_archs.x86_64 import CompilerArchX86_64


class CompilerArchX86(CompilerArchX86_64):
    def __init__(self):
        super().__init__()

    def get_gcc_flags(self):
        return super().get_gcc_flags() + [
            "-m32",
        ]

    def compiler_arch_option(self) -> [CompilerArchOption]:
        return [CompilerArchOption.X86, CompilerArchOption.X86_64]
