from subprocess import check_call
from pathlib import Path


sources_location = Path("/home/shay/Documents/Projects/Shellcode_Blocks/src")


def check_call_print(*args, **kwargs):
    print("[*] Running `", " ".join(args[0]), "`")

    check_call(*args, **kwargs)
