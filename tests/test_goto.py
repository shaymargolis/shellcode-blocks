import pytest

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.goto import ShellcodePrimitiveGoto


SECTOR_SIZE = 0x2000


@pytest.mark.parametrize('goto_page_and_address', [
    (0x81000000, 0x81000010),
    (0xbc000000, 0xbc000010),
    (0xbc000000, 0xbcf00010),
    # Case where the lower half is negative (0xfff0)
    # should still work as expected
    (0xbc00f000, 0xbcf0fff0),
    (0x91000000, 0x91000118),
])
def test_goto_sanity(get_mu, temp_dir_path, arch_helper, compiler_arch, goto_page_and_address):
    # Generate shellcode
    # ------------------
    shellcode_address = 0xbfc00000
    goto_page, goto_address = goto_page_and_address

    step = ShellcodeStep(
        "first_step",
        [
            ShellcodePrimitiveGoto("copy_next_stage", goto_address),
        ],
        0x1000,
        base_address=shellcode_address,
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    shellcode = out_file.read_bytes()

    # Try to run shellcode
    # --------------------

    mu = get_mu()
    mu.mem_map(shellcode_address, 0x2000)

    # write machine code to be emulated to memory
    mu.mem_write(shellcode_address, shellcode)

    mu.emu_start(shellcode_address, goto_address)

    assert goto_address == arch_helper.get_curr_pc(mu)


@pytest.mark.parametrize('shellcode_run_addr', [
    (0x81000010),
    (0xbc000010),
    (0xbcf00010),
    (0x91000118),
])
def test_goto_is_pic(get_mu, temp_dir_path, arch_helper, compiler_arch, shellcode_run_addr):
    # Generate shellcode
    # ------------------
    shellcode_address = 0xbfc00000
    _, goto_address = (0xbc000000, 0xbc000010)

    shellcode_run_sector = int(shellcode_run_addr/SECTOR_SIZE) * SECTOR_SIZE

    step = ShellcodeStep(
        "first_step",
        [
            ShellcodePrimitiveGoto("copy_next_stage", goto_address),
        ],
        0x1000,
        base_address=shellcode_address,
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    shellcode = out_file.read_bytes()

    # Try to run shellcode
    # --------------------

    mu = get_mu()
    mu.mem_map(shellcode_run_sector, 0x2000)

    # write machine code to be emulated to memory
    mu.mem_write(shellcode_run_addr, shellcode)

    mu.emu_start(shellcode_run_addr, goto_address)

    assert goto_address == arch_helper.get_curr_pc(mu)
