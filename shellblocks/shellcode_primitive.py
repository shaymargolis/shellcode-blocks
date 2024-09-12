import shutil
from pathlib import Path

from shellblocks.utils import check_call_print, sources_location


class ShellcodePrimitive:
    def __init__(self, nickname: str, sources: [str], code_file: str, header_file: str):
        self.nickname = nickname
        self.sources = sources
        self.header_file = header_file

    def generate_header_file(self, path: Path):
        header_path = path / self.header_file
        header_dict = self.header_requirements()

        header_define = f"HEADER_{self.nickname.upper()}_H"
        contents = []
        contents += [f"#ifndef {header_define}"]
        contents += [f"#define {header_define}"]
        contents += [""]

        for key, val in header_dict.items():
            if isinstance(val, int):
                contents += [f"#define {key} ({hex(val)})"]
            elif isinstance(val, str):
                contents += [f"#define {key} \"{val}\""]
            else:
                raise Exception(f"Cannot write header! Bad type {type(val)}")

        contents += [""]
        contents += [f"#endif // !{header_define}"]
        contents += [""]  # Empty line at EOF

        header_path.write_text("\n".join(contents))

    def header_requirements(self):
        return {}

    def generate(self, path: Path):
        for source in self.sources:
            source_src = sources_location / source
            source_dst = path / source

            shutil.copy(source_src, source_dst)

        self.generate_header_file(path)

        check_call_print([
            "mips-linux-gnu-gcc-9",
            "-nostdlib",
            "-ffreestanding",
            "-mno-shared",
            "-c", self.sources[0],
            "-o", "final.o",
            "-O3"
        ], cwd=path.as_posix())

        check_call_print([
            "objcopy",
            f"--redefine-sym=start={self.nickname}",
            "final.o"
        ], cwd=path.as_posix())

        return path / "final.o"
