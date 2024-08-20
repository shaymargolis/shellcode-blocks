# Shellcode Blocks

This repo allows you to concatenate shellcodes, running from different address spaces and links between them.
Each shellcode will ensure the next will run, and will constitute from various primitives.

For starters, we will only support MIPS (le/be).

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
    0xbfc00000,
    [
        ShellcodePrimitiveMemcpy("copy_next_stage", 0x80abcdef, 0x8f0ed0b0, 0x100),
        ShellcodePrimitivePrint("print_debug", 0x80901234, "This is a print!\\n"),
        ShellcodePrimitiveGoto("goto_next_stage", 0x801bc00f)
    ],
    0x1000
)

# This returns a final shellcode (raw bin), which relocation address is 0xbfc00000,
# That:
# 1. Copies 0x100 bytes from 0x80abcdef to 0x8f0ed0b0
# 2. Prints "This is a print!" using printf func at 0x80901234
# 3. Jumps to 0x801bc00f
first_step_out = first_step.generate(Path("/tmp/build") / step.nickname)
```

## Left todo

| task                                                  | is it done |
|-----------------------------------------------------  |------------|
| Gemerate example shellcode step using primitives      | ☑          |
| Generate shellcodes using python script without make  | ☑          |
| How to link between memcpy in stage to the next stage | ☑          |
| Units tests using unicorn or something?               | ☐          |

