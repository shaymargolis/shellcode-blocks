import pytest

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.jump_hook import ShellcodePrimitiveJumpHook


SECTOR_SIZE = 0x2000


@pytest.mark.parametrize('shellcode_run_addr', [
    (0x82000010),
    (0xbc100010),
    (0xbcd00010),
    (0x91100118),
])
@pytest.mark.parametrize('jump_hook_location', [
    0x81000010,
    0xbc000010,
    0xbcf00010,
    0x91000118,
])
@pytest.mark.parametrize('jump_hook_goto', [
    0x81002020,
    0xbc002020,
    0xbcf00070,
    0x910f0218,
])
def test_jump_hook_sanity(
    get_mu,
    arch_helper,
    temp_dir_path,
    compiler_arch,
    shellcode_run_addr,
    jump_hook_location,
    jump_hook_goto
):
    # Generate shellcode
    # ------------------
    shellcode_address = 0xbfc00000
    jump_hook_sector = int(jump_hook_location/SECTOR_SIZE) * SECTOR_SIZE
    shellcode_run_sector = int(shellcode_run_addr/SECTOR_SIZE) * SECTOR_SIZE

    step = ShellcodeStep(
        "first_step",
        shellcode_address,
        [
            ShellcodePrimitiveJumpHook(
                "hook_next_stage",
                jump_hook_location,
                jump_hook_goto
            ),
        ],
        0x1000
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    shellcode = out_file.read_bytes()

    EXPECTED_HOOK = arch_helper.get_jump_hook_bytes(jump_hook_goto)

    # Try to run shellcode
    # --------------------

    mu = get_mu()
    mu.mem_map(shellcode_run_sector, 0x2000)
    mu.mem_map(jump_hook_sector, 0x2000)

    # write machine code to be emulated to memory
    mu.mem_write(shellcode_run_addr, shellcode)
    mu.mem_write(jump_hook_sector, b"\x00" * 0x1000)

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(shellcode_run_addr, shellcode_run_addr + len(shellcode))

    assert mu.mem_read(jump_hook_location, len(EXPECTED_HOOK)) == EXPECTED_HOOK
    assert mu.mem_read(jump_hook_location+len(EXPECTED_HOOK), 1) == (b"\x00")
