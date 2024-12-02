from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_29, UC_MIPS_REG_4

from shellblocks.compiler_archs import CompilerArchOption


class ArchHelper:
    def __init__(self, compiler_arch_option):
        self.compiler_arch_option = compiler_arch_option


class MIPSHelper(ArchHelper):
    def __init__(self, compiler_arch_option):
        super().__init__(compiler_arch_option)

        assert compiler_arch_option in [
            CompilerArchOption.MIPSBE,
            CompilerArchOption.MIPSLE,
        ]

    def get_jump_hook_bytes(self, jump_hook_goto):
        EXPECTED_HOOK = [
            0x3c020000 + (jump_hook_goto >> 16),
            0x24420000 + (jump_hook_goto & 0xffff),
            0x00400008,
            0x00000000,
        ]

        if CompilerArchOption.MIPSBE == self.compiler_arch_option:
            return b"".join(map(lambda x: x.to_bytes(4, 'big'), EXPECTED_HOOK))
        elif CompilerArchOption.MIPSLE == self.compiler_arch_option:
            return b"".join(map(lambda x: x.to_bytes(4, 'little'), EXPECTED_HOOK))
        else:
            raise NotImplementedError()

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
