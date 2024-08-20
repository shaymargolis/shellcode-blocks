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
shellcodes = {
	"first_shellcode": ShellcodeStep([
		ShellcodePrimitive("memcpy", [src, dst, len]),
		ShellcodePrimitive("jump_hook", [src, dst]),
		ShellcodePrimitive("goto", [second_stage]),
	], first_base_address),
	"second_shellcode": ShellcodeStep([
		ShellcodePrimitive("memcpy", [src, dst, len]),
		ShellcodePrimitive("jump_hook", [src, dst]),
		ShellcodePrimitive("goto", [third_stage]),
	], second_base_address),
}
```

## Left todo

| task                                                  | is it done |
|-----------------------------------------------------  |------------|
| Gemerate example shellcode step using primitives      | ☑          |
| Generate shellcodes using python script without make  | ☐          |
| How to link between memcpy in stage to the next stage | ☐          |
| Units tests using unicorn or something?               | ☐          |

