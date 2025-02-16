import pytest
import os

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.memset import ShellcodePrimitiveMemset


SECTOR_SIZE = 0x2000


class UcMemsetHelper:
    def __init__(self,
                 get_mu,
                 arch_helper,
                 shellcode_address,
                 copy_addr,
                 stack_address):
        self.shellcode_address = shellcode_address
        self.arch_helper = arch_helper

        self.copy_addr = copy_addr
        self.copy_sector = int(self.copy_addr/SECTOR_SIZE) * SECTOR_SIZE

        self.mu = get_mu()
        self.mu.mem_map(self.shellcode_address, SECTOR_SIZE)
        self.mu.mem_map(self.copy_sector, SECTOR_SIZE)
        self.mu.mem_map(stack_address, 0x2000)

        self.arch_helper.set_curr_sp(self.mu, stack_address + 0x2000)

    def write_shellcode(self, shellcode):
        self.mu.mem_write(self.shellcode_address, shellcode)


@pytest.fixture()
def stack_address():
    return 0x80001000


@pytest.fixture(scope='function')
def default_memset_helper(get_mu, arch_helper, stack_address):
    return UcMemsetHelper(
        get_mu,
        arch_helper,
        0xbfc00000,
        0x82000010,
        stack_address
    )


def memset_get_shellcode(temp_dir_path, compiler_arch, memset_helper, copy_bytes):
    helper = memset_helper

    step = ShellcodeStep(
        "first_step",
        [
            ShellcodePrimitiveMemset(
                "copy_next_stage",
                helper.copy_addr,
                copy_bytes
            ),
        ],
        0x1000,
        base_address=helper.shellcode_address
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    shellcode = out_file.read_bytes()

    return shellcode


@pytest.mark.parametrize('copy_len', [
    100,
    200,
    0,
    1,
    2,
    3,
    8,
    16,
    32,
])
def test_memset_sanity(temp_dir_path, compiler_arch, default_memset_helper, copy_len):
    helper = default_memset_helper
    to_write = b"\xAA" * copy_len
    shellcode = memset_get_shellcode(temp_dir_path, compiler_arch, helper, to_write)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(helper.shellcode_address, shellcode)
    helper.mu.mem_write(helper.copy_addr, b"\x00" * copy_len)

    helper.mu.emu_start(helper.shellcode_address, helper.shellcode_address + len(shellcode))

    assert helper.mu.mem_read(helper.copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.copy_addr, copy_len) == to_write
    assert helper.mu.mem_read(helper.copy_addr + copy_len, 1) == b"\x00"


@pytest.mark.parametrize('shellcode_run_addr', [
    (0x83000010),
    (0xbc000010),
    (0xbcf00010),
    (0x91000118),
])
def test_memset_is_pic(temp_dir_path, compiler_arch, shellcode_run_addr, default_memset_helper):
    copy_len = 200
    helper = default_memset_helper
    to_write = b"\xAA" * copy_len
    shellcode = memset_get_shellcode(temp_dir_path, compiler_arch, helper, to_write)

    shellcode_run_sector = int(shellcode_run_addr/SECTOR_SIZE) * SECTOR_SIZE
    helper.mu.mem_map(shellcode_run_sector, SECTOR_SIZE)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(shellcode_run_addr, shellcode)
    helper.mu.mem_write(helper.copy_addr, b"\x00" * copy_len)

    helper.mu.emu_start(shellcode_run_addr, shellcode_run_addr + len(shellcode))

    assert helper.mu.mem_read(helper.copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.copy_addr, copy_len) == (b"\xAA" * copy_len)
    assert helper.mu.mem_read(helper.copy_addr + copy_len, 1) == b"\x00"


@pytest.mark.parametrize('copy_len', [
    100,
    200,
    2,
    4,
    8,
    12,
    16,
    20,
    24,
    28,
    32,
    100
])
def test_memset_two_halves(temp_dir_path, compiler_arch, default_memset_helper, copy_len):
    half_copy_len = int(copy_len/2)

    helper = default_memset_helper
    to_write = b"\xAA" * half_copy_len + b"\xBB" * half_copy_len
    shellcode = memset_get_shellcode(temp_dir_path, compiler_arch, helper, to_write)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(helper.shellcode_address, shellcode)
    helper.mu.mem_write(helper.copy_addr, b"\x00" * 2 * copy_len)

    helper.mu.emu_start(helper.shellcode_address, helper.shellcode_address + len(shellcode))

    assert helper.mu.mem_read(helper.copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.copy_addr, copy_len) == to_write
    assert helper.mu.mem_read(helper.copy_addr + copy_len, 1) == b"\x00"


@pytest.mark.parametrize('copy_len', [
    100,
    200,
    2,
    4,
    8,
    12,
    16,
    20,
    24,
    28,
    32,
    100
])
def test_memset_random(temp_dir_path, compiler_arch, default_memset_helper, copy_len):
    helper = default_memset_helper
    to_write = os.urandom(copy_len)
    shellcode = memset_get_shellcode(temp_dir_path, compiler_arch, helper, to_write)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(helper.shellcode_address, shellcode)
    helper.mu.mem_write(helper.copy_addr, b"\x00" * 2 * copy_len)

    helper.mu.emu_start(helper.shellcode_address, helper.shellcode_address + len(shellcode))

    assert helper.mu.mem_read(helper.copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.copy_addr, copy_len) == to_write
    assert helper.mu.mem_read(helper.copy_addr + copy_len, 1) == b"\x00"
