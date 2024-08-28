import pytest

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.memcpy import ShellcodePrimitiveMemcpy


def test_step_too_large_fails(temp_dir_path):
    step = ShellcodeStep(
        "first_step",
        0x1000,
        [
            ShellcodePrimitiveMemcpy(
                f"copy_next_stage{i}",
                0x2000,
                0x3000,
                0x10
            )
            for i in range(6)
        ],
        0x10
    )

    with pytest.raises(Exception):
        step.generate(temp_dir_path / step.nickname)
