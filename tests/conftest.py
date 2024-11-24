import pytest

from tempfile import TemporaryDirectory

from pathlib import Path

from unicorn import (
    Uc,
    UC_ARCH_MIPS,
    UC_MODE_32,
    UC_MODE_BIG_ENDIAN,
    UC_MODE_LITTLE_ENDIAN,
)


from shellblocks.test_arch_helper import MIPSHelper

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
    else:
        raise NotImplementedError("Arch unimplemented error!")


@pytest.fixture
def get_mu(compiler_arch_option):
    def get_mu_instance():
        if CompilerArchOption.MIPSBE == compiler_arch_option:
            return Uc(UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_BIG_ENDIAN)
        elif CompilerArchOption.MIPSLE == compiler_arch_option:
            return Uc(UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_LITTLE_ENDIAN)
        else:
            raise NotImplementedError("Arch unimplemented error!")

    return get_mu_instance


@pytest.fixture(scope='function')
def temp_dir_path():
    tempdir = TemporaryDirectory()
    yield Path(tempdir.name)
    tempdir.cleanup()
