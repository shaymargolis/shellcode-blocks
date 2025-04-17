# Shellcode Blocks

## build status [![Python application](https://github.com/shaymargolis/shellcode-blocks/actions/workflows/build-test.yml/badge.svg)](https://github.com/shaymargolis/shellcode-blocks/actions/workflows/build-test.yml)

## What is this repo?

Allows you to write PIC and fast shellcodes in C! keeping your logic simple, easy to expand, test and maintain.
Shellcodes are seperated to "primitives", each one provides a behavior, and to create a full grown shellcode you can concatenate multiple primitives, or to create one primtives doing all of your logic.

Supported architectures:

- X86 and X64
- Mips (LE and BE)
- Arm 32bit

Adding another architecture is very simple!

## What does this mean?

For example, see our implementation of goto:

```c
void start(void) {
    void (*goto_address)() = (void (*)())(GOTO_ADDRESS);

    goto_address();
}
```

Our implementation of memcpy:

```c
void __attribute__((noreturn)) start(void) {
    u8 *src = (u8 *)MEMCPY_SOURCE_ADDRESS;
    u8 *dst = (u8 *)MEMCPY_DEST_ADDRESS;
    u32 len = (u32)MEMCPY_LEN;

    u8 *end = src + len;

    while (src < end - 1) {
        *dst = *src;
        src++;
        dst++;
    }

    *dst = *src;

    __builtin_unreachable();
}
```

Super easy and to write even more complex code!

## Shellcode primitives

- Memcpy (Src Addr, Dst Addr, Len)
- Put jump hook to address somewhere
- Call print function
- Customized primitives

## Concatenating primitives

A final "Shellcode Structure" example:

```python
first_step = ShellcodeStep(
    "first_step",
    [
        ShellcodePrimitiveMemcpy("copy_next_stage", 0x80abcdef, 0x8f0ed0b0, 0x100),
        ShellcodePrimitivePrint("print_debug", 0x80901234, "This is a print!\n"),
        ShellcodePrimitiveJumpHook("put_jmp_hook", 0x80901234, 0x8f0ed0b0),
        ShellcodePrimitiveGoto("goto_next_stage", 0x801bc00f),
    ],
    0x1000
)

# This returns a final shellcode (raw bin), which relocation address is 0xbfc00000,
# That:
# 1. Copies 0x100 bytes from 0x80abcdef to 0x8f0ed0b0
# 2. Prints "This is a print!" using printf func at 0x80901234
# 3. Puts jump hook on 0x80901234, that will jump to 0x8f0ed0b0
# 4. Jumps to 0x801bc00f
first_step_out = first_step.generate(Path("/tmp/build") / step.nickname)
```

## How it works?

1. The primitive is a C function or an assembly snippet.
2. The primitive is getting compiled to a relocatable object file using `-O3`
3. Each ShellcodeStep combines all primitives and relocates them to the given base address

## Requirements

```
sudo apt install gcc-9-mips-linux-gnu binutils-multiarch
```

## Left todo

| task                                                  | is it done |
|-----------------------------------------------------  |------------|
| Gemerate example shellcode step using primitives      | ☑          |
| Generate shellcodes using python script without make  | ☑          |
| How to link between memcpy in stage to the next stage | ☑          |
| Units tests using unicorn or something?               | ☑          |


## Known issues

Currently none!
