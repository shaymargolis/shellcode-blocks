from pathlib import Path

from shellblocks.compiler_arch import CompilerArch
from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.goto import ShellcodePrimitiveGoto
from shellblocks.primitives.memset import ShellcodePrimitiveMemset


class ShellcodePrimitiveJumpHook(ShellcodePrimitiveMemset):
    """
    JumpHook is implemented using MEMSETing hook_address with
    GOTO primitive to goto_address.
    """

    def __init__(self, nickname: str, hook_address: int, goto_address: int):
        super().__init__(
            nickname,
            hook_address,
            bytes()  # This will be generated at "generate"
        )

        self.goto_address = goto_address

    def generate(self, path: Path, compiler: CompilerArch):
        step = ShellcodeStep(
            self.nickname,
            0x0,  # This should be PIC
            [
                ShellcodePrimitiveGoto(
                    self.nickname,
                    self.goto_address
                ),
            ],
            0x1000
        )

        out_file = step.generate(path / self.nickname / "goto_temp", compiler)
        self.set_bytes = out_file.read_bytes()

        return super().generate(path, compiler)
