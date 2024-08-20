from shellblocks.shellcode_primitive import ShellcodePrimitive

class ShellcodePrimitivePrint(ShellcodePrimitive):
    def __init__(self, nickname: str, print_function: int, print_string: str):
        super().__init__(
            nickname,
            ["print.c", "utils.h"],
            "print.c",
            "print.h"
        )

        self.print_function = print_function
        self.print_string = print_string

    def header_requirements(self):
        return {
            "PRINT_FUNCTION_ADDRESS": self.print_function,
            "PRINT_STRING": self.print_string,
        }
