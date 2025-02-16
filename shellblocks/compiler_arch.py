from typing import List
from shellblocks.compiler_arch_option import CompilerArchOption


class CompilerArch():
    def __init__(self):
        pass

    def compiler_arch_option(self) -> [CompilerArchOption]:
        raise NotImplementedError()

    def compile_primitive(self, src_path: str) -> List[str]:
        raise NotImplementedError()

    def compile_step(self, src_paths: List[str], base_address: int) -> List[str]:
        raise NotImplementedError()

    def get_headers(self) -> List[str]:
        raise NotImplementedError()
