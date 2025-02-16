import pytest

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.memcpy import ShellcodePrimitiveMemcpy


SECTOR_SIZE = 0x2000


class UcMemcpyHelper:
    def __init__(self,
                 get_mu,
                 shellcode_address,
                 first_copy_addr,
                 second_copy_addr):
        self.shellcode_address = shellcode_address

        self.first_copy_addr = first_copy_addr
        self.first_sector = int(self.first_copy_addr/SECTOR_SIZE) * SECTOR_SIZE

        self.second_copy_addr = second_copy_addr
        self.second_sector = int(self.second_copy_addr/SECTOR_SIZE) * SECTOR_SIZE

        self.mu = get_mu()
        self.mu.mem_map(self.shellcode_address, SECTOR_SIZE)
        self.mu.mem_map(self.first_sector, SECTOR_SIZE)
        self.mu.mem_map(self.second_sector, SECTOR_SIZE)

    def write_shellcode(self, shellcode):
        self.mu.mem_write(self.shellcode_address, shellcode)


@pytest.fixture(scope='function')
def default_memcpy_helper(get_mu):
    return UcMemcpyHelper(
        get_mu,
        0xbfc00000,
        0x81000010,
        0x82000010
    )


def memcpy_get_shellcode(temp_dir_path, compiler_arch, memcpy_helper, copy_len):
    helper = memcpy_helper

    step = ShellcodeStep(
        "first_step",
        [
            ShellcodePrimitiveMemcpy(
                "copy_next_stage",
                helper.first_copy_addr,
                helper.second_copy_addr,
                copy_len
            ),
        ],
        0x1000,
        base_address=helper.shellcode_address,
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    shellcode = out_file.read_bytes()

    return shellcode


@pytest.mark.parametrize('copy_len', [
    100,
    200,
    0x1000,
    0,
    1,
    2,
    3,
    100
])
def test_memcpy_sanity(temp_dir_path, compiler_arch, default_memcpy_helper, copy_len):
    helper = default_memcpy_helper
    shellcode = memcpy_get_shellcode(temp_dir_path, compiler_arch, helper, copy_len)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(helper.shellcode_address, shellcode)
    helper.mu.mem_write(helper.first_copy_addr, b"\xAA" * copy_len)
    helper.mu.mem_write(helper.second_copy_addr, b"\x00" * copy_len)

    helper.mu.emu_start(helper.shellcode_address, helper.shellcode_address + len(shellcode))

    assert helper.mu.mem_read(helper.second_copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.second_copy_addr, copy_len) == (b"\xAA" * copy_len)
    assert helper.mu.mem_read(helper.second_copy_addr + copy_len, 1) == b"\x00"


@pytest.mark.parametrize('shellcode_run_addr', [
    (0x83000010),
    (0xbc000010),
    (0xbcf00010),
    (0x91000118),
])
def test_memcpy_is_pic(temp_dir_path, compiler_arch, shellcode_run_addr, default_memcpy_helper):
    copy_len = 0x1000
    helper = default_memcpy_helper
    shellcode = memcpy_get_shellcode(temp_dir_path, compiler_arch, helper, copy_len)

    shellcode_run_sector = int(shellcode_run_addr/SECTOR_SIZE) * SECTOR_SIZE
    helper.mu.mem_map(shellcode_run_sector, SECTOR_SIZE)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(shellcode_run_addr, shellcode)
    helper.mu.mem_write(helper.first_copy_addr, b"\xAA" * copy_len)
    helper.mu.mem_write(helper.second_copy_addr, b"\x00" * copy_len)

    helper.mu.emu_start(shellcode_run_addr, shellcode_run_addr + len(shellcode))

    assert helper.mu.mem_read(helper.second_copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.second_copy_addr, copy_len) == (b"\xAA" * copy_len)
    assert helper.mu.mem_read(helper.second_copy_addr + copy_len, 1) == b"\x00"


@pytest.mark.parametrize('copy_len', [
    100,
    200,
    0x600,
    2,
    3,
    100
])
def test_memcpy_short(temp_dir_path, compiler_arch, default_memcpy_helper, copy_len):

    helper = default_memcpy_helper
    shellcode = memcpy_get_shellcode(temp_dir_path, compiler_arch, helper, copy_len)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(helper.shellcode_address, shellcode)
    helper.mu.mem_write(helper.first_copy_addr, b"\xAA" * 2 * copy_len)
    helper.mu.mem_write(helper.second_copy_addr, b"\x00" * 2 * copy_len)

    helper.mu.emu_start(helper.shellcode_address, helper.shellcode_address + len(shellcode))

    assert helper.mu.mem_read(helper.second_copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.second_copy_addr, copy_len) == (b"\xAA" * copy_len)
    assert helper.mu.mem_read(helper.second_copy_addr + copy_len, 1) == b"\x00"


@pytest.mark.parametrize('copy_len', [
    100,
    200,
    0x600,
    2,
    4,
    100
])
def test_memcpy_two_halves(temp_dir_path, compiler_arch, default_memcpy_helper, copy_len):
    half_copy_len = int(copy_len/2)

    helper = default_memcpy_helper
    shellcode = memcpy_get_shellcode(temp_dir_path, compiler_arch, helper, copy_len)

    # Try to run shellcode
    # --------------------

    # write machine code to be emulated to memory
    helper.mu.mem_write(helper.shellcode_address, shellcode)
    helper.mu.mem_write(helper.first_copy_addr, b"\xAA" * half_copy_len + b"\xBB" * half_copy_len)
    helper.mu.mem_write(helper.second_copy_addr, b"\x00" * 2 * copy_len)

    helper.mu.emu_start(helper.shellcode_address, helper.shellcode_address + len(shellcode))

    assert helper.mu.mem_read(helper.second_copy_addr - 1, 1) == b"\x00"
    assert helper.mu.mem_read(helper.second_copy_addr, copy_len) == (b"\xAA" * half_copy_len + b"\xBB" * half_copy_len)
    assert helper.mu.mem_read(helper.second_copy_addr + copy_len, 1) == b"\x00"
