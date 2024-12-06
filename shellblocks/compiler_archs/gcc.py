from shellblocks.compiler_arch import CompilerArch


class CompilerArchGCC(CompilerArch):
    def __init__(self):
        super().__init__()

        self.compiler_path = self.get_compiler_path()

    def get_compiler_path(self):
        raise NotImplementedError()

    def get_ldscript_path(self):
        raise NotImplementedError()

    def get_gcc_flags(self):
        return [
            "-nostdlib",
            "-ffreestanding",
            # Require GCC to keep the compilation order
            # as declared in the source files
            "-fno-toplevel-reorder",
        ]

    def compile_primitive(self, src_path: str) -> [str]:
        return [
            self.compiler_path,
            *self.get_gcc_flags(),
            "-c", src_path,
            "-o", "final.o",
            "-O3"
        ]

    def compile_step(self, src_paths: [str], base_address: int) -> [str]:
        ldscript_loc = self.get_ldscript_path()

        return [
            self.compiler_path,
            *src_paths,
            "-o", "shellcode.elf",
            *self.get_gcc_flags(),
            f"-Wl,--section-start=.text={hex(base_address)}",
            f"-Wl,-T{ldscript_loc}"
        ]
