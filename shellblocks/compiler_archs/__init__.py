from enum import Enum
from shellblocks.compiler_archs.mips import CompilerArchMIPSBE, CompilerArchMIPSLE
from shellblocks.compiler_arch import CompilerArch


class CompilerArchOption(Enum):
    MIPSBE = "mipsbe"
    MIPSLE = "mipsle"


def compiler_arch_to_object(arch: CompilerArchOption) -> CompilerArch:
    if arch == CompilerArchOption.MIPSBE:
        return CompilerArchMIPSBE()
    elif arch == CompilerArchOption.MIPSLE:
        return CompilerArchMIPSLE()

    raise NotImplementedError()


__all__ = [
    CompilerArchMIPSBE, CompilerArchMIPSLE,
]
