import shutil
from pathlib import Path


from shellblocks.compiler_arch import CompilerArch
from shellblocks.shellcode_primitive import ShellcodePrimitive
from shellblocks.utils import check_call_print


class ShellcodeStep:
    def __init__(self, nickname: str, base_address: int, primitives: [ShellcodePrimitive], max_len: int):
        self.nickname = nickname
        self.base_address = base_address
        self.primitives = primitives
        self.max_len = max_len

    def generate(self, build_dir: Path, compiler: CompilerArch):
        # Create build dir
        try:
            shutil.rmtree(build_dir.as_posix())
        except FileNotFoundError:
            pass

        build_dir.mkdir(parents=True, exist_ok=True)

        # Generate primitives elf files
        out_files = []

        for p in self.primitives:
            p_build_dir = build_dir / p.nickname
            p_build_dir.mkdir()

            out_file = p.generate(p_build_dir, compiler)
            out_files.append(out_file.as_posix())

        # Join all primitives to final shellcode
        check_call_print(
            compiler.compile_step(out_files, self.base_address),
            cwd=build_dir.as_posix()
        )

        check_call_print([
            "objcopy",
            "-O", "binary",
            "-j", ".text",
            "-j", ".rodata",
            "shellcode.elf",
            "final_shellcode.bin",
        ], cwd=build_dir.as_posix())

        # Verify outfile is valid
        outfile_path = build_dir / "final_shellcode.bin"
        assert outfile_path.stat().st_size < self.max_len

        return outfile_path
