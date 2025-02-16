from subprocess import check_output, CalledProcessError
from enum import Enum


class CompilerArchOption(Enum):
    MIPSBE = "mipsbe"
    MIPSLE = "mipsle"
    ARMLE = "armle"
    X86 = "x86"
    X86_64 = "x86_64"
    POWERPCLE = "powerpcle"


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
    if "powerpc64le-" in machine:
        return CompilerArchOption.POWERPCLE

    return None
