import pytest

from tempfile import TemporaryDirectory

from pathlib import Path

from unicorn import (
    Uc,
    UC_ARCH_MIPS,
    UC_ARCH_ARM,
    UC_ARCH_X86,
    UC_MODE_ARM,
    UC_ARCH_PPC,
    UC_MODE_32,
    UC_MODE_64,
    UC_MODE_BIG_ENDIAN,
    UC_MODE_LITTLE_ENDIAN,
    UC_MODE_PPC32,
)


from shellblocks.test_arch_helper import MIPSHelper, ARMHelper, X86Helper, PowerPCHelper

from shellblocks.compiler_archs import CompilerArchOption, compiler_arch_to_object


def pytest_addoption(parser):
    choices = [e.value for e in CompilerArchOption]

    parser.addoption(
        "--compiler-arch",
        type=str,
        choices=choices,
        default=CompilerArchOption.MIPSBE.value,
        help="The architecture to compile to"
    )


@pytest.fixture
def compiler_arch_option(request):
    return CompilerArchOption(request.config.getoption("--compiler-arch"))


@pytest.fixture
def compiler_arch(compiler_arch_option):
    return compiler_arch_to_object(compiler_arch_option)


@pytest.fixture
def arch_helper(compiler_arch_option):
    if compiler_arch_option in [CompilerArchOption.MIPSBE, CompilerArchOption.MIPSLE]:
        return MIPSHelper(compiler_arch_option)
    if compiler_arch_option in [CompilerArchOption.ARMLE]:
        return ARMHelper(compiler_arch_option)
    if compiler_arch_option in [CompilerArchOption.X86, CompilerArchOption.X86_64]:
        return X86Helper(compiler_arch_option)
    if compiler_arch_option in [CompilerArchOption.POWERPCLE]:
        return PowerPCHelper(compiler_arch_option)
    else:
        raise NotImplementedError("Arch unimplemented error!")


@pytest.fixture
def get_mu(compiler_arch_option):
    def get_mu_instance():
        if CompilerArchOption.MIPSBE == compiler_arch_option:
            return Uc(UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_BIG_ENDIAN)
        elif CompilerArchOption.MIPSLE == compiler_arch_option:
            return Uc(UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_LITTLE_ENDIAN)
        elif CompilerArchOption.ARMLE == compiler_arch_option:
            return Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
        elif CompilerArchOption.X86 == compiler_arch_option:
            return Uc(UC_ARCH_X86, UC_MODE_32)
        elif CompilerArchOption.X86_64 == compiler_arch_option:
            return Uc(UC_ARCH_X86, UC_MODE_64)
        elif CompilerArchOption.POWERPCLE == compiler_arch_option:
            return Uc(UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN)
        else:
            raise NotImplementedError("Arch unimplemented error!")

    return get_mu_instance


@pytest.fixture(scope='function')
def temp_dir_path():
    tempdir = TemporaryDirectory()
    yield Path(tempdir.name)
    tempdir.cleanup()
