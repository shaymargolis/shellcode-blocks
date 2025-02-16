from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_29, UC_MIPS_REG_4
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_R0
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_RDI

from shellblocks.compiler_archs import CompilerArchOption


class ArchHelper:
    def __init__(self, compiler_arch_option):
        self.compiler_arch_option = compiler_arch_option


class X86Helper(ArchHelper):
    def __init__(self, compiler_arch_option):
        super().__init__(compiler_arch_option)

        assert compiler_arch_option in [
            CompilerArchOption.X86,
            CompilerArchOption.X86_64,
        ]

        self.word_size = 4

        if CompilerArchOption.X86_64 == self.compiler_arch_option:
            self.word_size = 8

    def get_ret_bytes(self):
        return b"\xc3"  # "ret" in x86

    def get_curr_pc(self, mu):
        return mu.reg_read(UC_X86_REG_EIP)

    def set_curr_sp(self, mu, new_stack):
        mu.reg_write(UC_X86_REG_ESP, new_stack)

    def get_curr_sp(self, mu):
        return mu.reg_read(UC_X86_REG_ESP)

    def get_curr_func_arg(self, mu, func_arg):
        if CompilerArchOption.X86_64 == self.compiler_arch_option:
            if func_arg == 0:
                return mu.reg_read(UC_X86_REG_RDI)

            raise NotImplementedError(f"Getting {func_arg} func arg")

        if CompilerArchOption.X86 == self.compiler_arch_option:
            # cdecl

            val = mu.mem_read(
                (mu.reg_read(UC_X86_REG_ESP)
                    + (func_arg + 1) * self.word_size), self.word_size
            )

            return int.from_bytes(val, 'little')

        raise NotImplementedError(
            "Only x86 or x86-64 calling conventions are implemented"
        )


class ARMHelper(ArchHelper):
    def __init__(self, compiler_arch_option):
        super().__init__(compiler_arch_option)

        assert compiler_arch_option in [
            CompilerArchOption.ARMLE,
        ]

    def get_ret_bytes(self):
        val = 0xe12fff1e  # "bx lr" in ARM

        if CompilerArchOption.ARMLE == self.compiler_arch_option:
            return val.to_bytes(4, 'little')
        else:
            raise NotImplementedError()

    def get_curr_pc(self, mu):
        return mu.reg_read(UC_ARM_REG_PC)

    def set_curr_sp(self, mu, new_stack):
        mu.reg_write(UC_ARM_REG_SP, new_stack)

    def get_curr_sp(self, mu):
        return mu.reg_read(UC_ARM_REG_SP)

    def get_curr_func_arg(self, mu, func_arg):
        if func_arg == 0:
            return mu.reg_read(UC_ARM_REG_R0)

        raise NotImplementedError(f"Getting {func_arg} func arg")


class MIPSHelper(ArchHelper):
    def __init__(self, compiler_arch_option):
        super().__init__(compiler_arch_option)

        assert compiler_arch_option in [
            CompilerArchOption.MIPSBE,
            CompilerArchOption.MIPSLE,
        ]

    def get_ret_bytes(self):
        val = 0x03e00008  # "jr $ra" in MIPS

        if CompilerArchOption.MIPSBE == self.compiler_arch_option:
            return val.to_bytes(4, 'big')
        elif CompilerArchOption.MIPSLE == self.compiler_arch_option:
            return val.to_bytes(4, 'little')
        else:
            raise NotImplementedError()

    def get_curr_pc(self, mu):
        return mu.reg_read(UC_MIPS_REG_PC)

    def set_curr_sp(self, mu, new_stack):
        mu.reg_write(UC_MIPS_REG_29, new_stack)

    def get_curr_sp(self, mu):
        return mu.reg_read(UC_MIPS_REG_29)

    def get_curr_func_arg(self, mu, func_arg):
        if func_arg == 0:
            return mu.reg_read(UC_MIPS_REG_4)

        raise NotImplementedError(f"Getting {func_arg} func arg")
