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
