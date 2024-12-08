from subprocess import check_output, CalledProcessError
from enum import Enum
from shellblocks.compiler_archs.mips import CompilerArchMIPSBE, CompilerArchMIPSLE
from shellblocks.compiler_archs.arm import CompilerArchARMLE
from shellblocks.compiler_archs.x86 import CompilerArchX86
from shellblocks.compiler_archs.x86_64 import CompilerArchX86_64
from shellblocks.compiler_arch import CompilerArch


class CompilerArchOption(Enum):
    MIPSBE = "mipsbe"
    MIPSLE = "mipsle"
    ARMLE = "armle"
    X86 = "x86"
    X86_64 = "x86_64"


def get_current_platform():
    try:
        machine_bytes = check_output(["gcc", "-dumpmachine"])
    except FileNotFoundError:
        return None
    except CalledProcessError:
        return None

    machine = machine_bytes.decode()

    if "mips-" in machine:
        return CompilerArchOption.MIPSBE
    if "mipsel-" in machine:
        return CompilerArchOption.MIPSLE
    if "arm-" in machine:
        return CompilerArchOption.ARMLE
    if "x86_64-" in machine:
        return CompilerArchOption.X86_64

    return None


def compiler_arch_to_object(arch: CompilerArchOption) -> CompilerArch:
    current_platform = get_current_platform()
    use_main_gcc = (current_platform == arch)

    if arch == CompilerArchOption.MIPSBE:
        return CompilerArchMIPSBE(use_main_gcc)
    elif arch == CompilerArchOption.MIPSLE:
        return CompilerArchMIPSLE(use_main_gcc)
    elif arch == CompilerArchOption.ARMLE:
        return CompilerArchARMLE(use_main_gcc)
    elif arch == CompilerArchOption.X86:
        return CompilerArchX86(CompilerArchOption.X86_64 == current_platform)
    elif arch == CompilerArchOption.X86_64:
        return CompilerArchX86_64(use_main_gcc)

    raise NotImplementedError()


__all__ = [
    CompilerArchMIPSBE, CompilerArchMIPSLE, CompilerArchARMLE,
]
