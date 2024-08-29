from shellblocks.shellcode_primitive import ShellcodePrimitive


class ShellcodePrimitivePrint(ShellcodePrimitive):
    def __init__(self, nickname: str, print_function: int, print_string: str):
        super().__init__(
            nickname,
            ["print.S", "utils.h"],
            "print.S",
            "print.h"
        )

        self.print_function = print_function
        self.print_string = print_string

    def header_requirements(self):
        string_c_format = self.print_string.encode(
            "unicode_escape"
        ).decode("utf-8")

        return {
            "PRINT_FUNCTION_ADDRESS": self.print_function,
            "PRINT_STRING": string_c_format,
        }
