import pytest

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.jump_hook import ShellcodePrimitiveJumpHook
from shellblocks.primitives.goto import ShellcodePrimitiveGoto
from shellblocks.primitives.memset import ShellcodePrimitiveMemset


SECTOR_SIZE = 0x2000


def generate_memset_to_goto(temp_dir_path,
                            shellcode_address,
                            compiler_arch,
                            jump_hook_goto,
                            jump_hook_location):
    expected_goto_primitive = ShellcodePrimitiveGoto(
        "jump_next_stage",
        jump_hook_goto
    )

    step = ShellcodeStep(
        "first_step",
        [
            expected_goto_primitive,
        ],
        0x1000,
        base_address=shellcode_address,
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    goto_shellcode = out_file.read_bytes()

    expected_memset_primitive = ShellcodePrimitiveMemset(
        "set_jump_next_stage",
        jump_hook_location,
        goto_shellcode
    )

    step = ShellcodeStep(
        "first_step",
        [
            expected_memset_primitive,
        ],
        0x1000,
        base_address=shellcode_address,
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    return out_file.read_bytes()


@pytest.mark.parametrize('shellcode_run_addr', [
    (0x82000010),
    (0xbc100010),
    (0x91100118),
])
@pytest.mark.parametrize('jump_hook_location', [
    0xbc000010,
    0x91000118,
])
@pytest.mark.parametrize('jump_hook_goto', [
    0x81002020,
    0xbcf00070,
    0x910f0218,
])
def test_jump_hook_sanity(
    temp_dir_path,
    compiler_arch,
    shellcode_run_addr,
    jump_hook_location,
    jump_hook_goto
):
    # Generate shellcode
    # ------------------
    shellcode_address = 0xbfc00000

    # Build expected MEMSET to GOTO

    memset_shellcode = generate_memset_to_goto(
        temp_dir_path,
        shellcode_address,
        compiler_arch,
        jump_hook_goto,
        jump_hook_location,
    )

    # Check is identical to JUMPHOOK primitive

    jump_hook_pritimive = ShellcodePrimitiveJumpHook(
        "hook_next_stage",
        jump_hook_location,
        jump_hook_goto
    )

    step = ShellcodeStep(
        "first_step",
        [
            jump_hook_pritimive,
        ],
        0x1000,
        base_address=shellcode_address
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    jump_hook_shellcode = out_file.read_bytes()

    assert jump_hook_shellcode == memset_shellcode
