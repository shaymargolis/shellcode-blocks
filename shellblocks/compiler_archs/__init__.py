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


def compiler_arch_to_object(arch: CompilerArchOption) -> CompilerArch:
    if arch == CompilerArchOption.MIPSBE:
        return CompilerArchMIPSBE()
    elif arch == CompilerArchOption.MIPSLE:
        return CompilerArchMIPSLE()
    elif arch == CompilerArchOption.ARMLE:
        return CompilerArchARMLE()
    elif arch == CompilerArchOption.X86:
        return CompilerArchX86()
    elif arch == CompilerArchOption.X86_64:
        return CompilerArchX86_64()

    raise NotImplementedError()


__all__ = [
    CompilerArchMIPSBE, CompilerArchMIPSLE, CompilerArchARMLE,
]
