import pytest

from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_32, UC_MODE_BIG_ENDIAN
from unicorn.mips_const import UC_MIPS_REG_PC

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.goto import ShellcodePrimitiveGoto


@pytest.mark.parametrize('goto_page_and_address', [
    (0x81000000, 0x81000010),
    (0xbc000000, 0xbc000010),
    (0xbc000000, 0xbcf00010),
    (0x91000000, 0x91000118),
])
def test_goto_sanity(temp_dir_path, goto_page_and_address):
    # Generate shellcode
    # ------------------
    shellcode_address = 0xbfc00000
    goto_page, goto_address = goto_page_and_address

    step = ShellcodeStep(
        "first_step",
        shellcode_address,
        [
            ShellcodePrimitiveGoto("copy_next_stage", goto_address),
        ],
        0x1000
    )

    out_file = step.generate(temp_dir_path / step.nickname)
    shellcode = out_file.read_bytes()

    # Try to run shellcode
    # --------------------

    mu = Uc(UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_BIG_ENDIAN)
    mu.mem_map(shellcode_address, 0x2000)
    mu.mem_map(0x81000000, 0x2000)

    # write machine code to be emulated to memory
    mu.mem_write(shellcode_address, shellcode)

    mu.emu_start(shellcode_address, goto_address)

    assert goto_address == mu.reg_read(UC_MIPS_REG_PC)
