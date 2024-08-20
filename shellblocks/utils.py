from subprocess import check_call
from pathlib import Path


sources_location = Path(__file__).parent / "src"


def check_call_print(*args, **kwargs):
    print("[*] Running `", " ".join(args[0]), "`")

    check_call(*args, **kwargs)
