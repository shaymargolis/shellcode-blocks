from shellblocks.compiler_archs.x86_64 import CompilerArchX86_64


class CompilerArchX86(CompilerArchX86_64):
    def __init__(self, use_main_gcc: bool):
        super().__init__(use_main_gcc)

    def get_gcc_flags(self):
        return super().get_gcc_flags() + [
            "-m32",
        ]
