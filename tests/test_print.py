import pytest

from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_29, UC_MIPS_REG_4

from shellblocks.shellcode_step import ShellcodeStep
from shellblocks.primitives.print import ShellcodePrimitivePrint


SECTOR_SIZE = 0x2000


print_function_addrs = [
    0x81000010,
    0xbc000010,
    0xbcf00010,
    0x91000118,
]

strings_to_print = [
    "This is a print!\n",
    "A B and C!\n",
    "you for real?\n",
]


@pytest.fixture()
def stack_address():
    return 0x80001000


@pytest.fixture(params=print_function_addrs)
def print_function_addr(request):
    return request.param


@pytest.fixture(params=strings_to_print)
def string_to_print(request):
    return request.param


@pytest.fixture()
def print_shellcode(compiler_arch, temp_dir_path, print_function_addr, string_to_print):
    # Generate shellcode
    # ------------------
    shellcode_address = 0xbfc00000

    step = ShellcodeStep(
        "first_step",
        shellcode_address,
        [
            ShellcodePrimitivePrint("print_stuff", print_function_addr, string_to_print),
        ],
        0x1000
    )

    out_file = step.generate(temp_dir_path / step.nickname, compiler_arch)
    shellcode = out_file.read_bytes()

    return shellcode, shellcode_address


def get_print_mu(
        get_mu,
        arch_helper,
        print_shellcode,
        shellcode_run_addr,
        print_function_addr,
        string_to_print,
        stack_address):
    shellcode, shellcode_address = print_shellcode

    print_function_sector = int(print_function_addr/SECTOR_SIZE) * SECTOR_SIZE
    shellcode_run_sector = int(shellcode_run_addr/SECTOR_SIZE) * SECTOR_SIZE

    # Try to run shellcode
    # --------------------

    mu = get_mu()

    # Print function uses the stack pointer
    mu.reg_write(UC_MIPS_REG_29, stack_address + 0x2000)

    mu.mem_map(shellcode_run_sector, 0x2000)
    mu.mem_map(print_function_sector, 0x2000)
    mu.mem_map(stack_address, 0x2000)

    # write machine code to be emulated to memory
    mu.mem_write(shellcode_run_addr, shellcode)
    mu.mem_write(print_function_addr, arch_helper.get_ret_bytes())

    return mu


def test_print_reaches_print_function(
    get_mu, arch_helper, print_shellcode, string_to_print, print_function_addr, stack_address
):
    shellcode, shellcode_address = print_shellcode
    print_mu = get_print_mu(
        get_mu,
        arch_helper,
        print_shellcode,
        shellcode_address,
        print_function_addr,
        string_to_print,
        stack_address
    )

    print_mu.emu_start(shellcode_address, print_function_addr)
    assert print_function_addr == print_mu.reg_read(UC_MIPS_REG_PC)

    # Check print string
    a0_reg_value = print_mu.reg_read(UC_MIPS_REG_4)  # First func argument
    string_value = bytes(
        print_mu.mem_read(a0_reg_value, len(string_to_print) + 1)
    )

    assert string_value == string_to_print.encode() + b"\x00"


def test_print_reaches_end(
        get_mu,
        arch_helper,
        print_shellcode,
        print_function_addr,
        string_to_print,
        stack_address):
    shellcode, shellcode_address = print_shellcode
    print_mu = get_print_mu(
        get_mu,
        arch_helper,
        print_shellcode,
        shellcode_address,
        print_function_addr,
        string_to_print,
        stack_address
    )

    print_mu.emu_start(shellcode_address, shellcode_address + len(shellcode))

    assert (stack_address + 0x2000) == print_mu.reg_read(UC_MIPS_REG_29)


@pytest.mark.parametrize('shellcode_run_addr', [
    (0x83000010),
    (0xbc300010),
    (0xbcf30010),
    (0x92000118),
])
def test_print_is_pic(
    get_mu,
    arch_helper,
    shellcode_run_addr,
    print_shellcode,
    print_function_addr,
    string_to_print,
    stack_address
):
    shellcode, shellcode_address = print_shellcode
    print_mu = get_print_mu(
        get_mu,
        arch_helper,
        print_shellcode,
        shellcode_run_addr,
        print_function_addr,
        string_to_print,
        stack_address
    )

    print_mu.emu_start(shellcode_run_addr, shellcode_run_addr + len(shellcode))
