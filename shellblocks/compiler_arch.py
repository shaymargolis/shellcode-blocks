class CompilerArch():
    def __init__(self):
        pass

    def compile_primitive(self, src_path: str) -> [str]:
        raise NotImplementedError()

    def compile_step(self, src_paths: [str], base_address: int) -> [str]:
        raise NotImplementedError()
