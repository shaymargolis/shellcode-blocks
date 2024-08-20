.print.bin:
    mips-linux-gnu-gcc-9 -c print.c -o print.o -O3

.memcpy.bin:
    mips-linux-gnu-gcc-9 -c memcpy.c -o memcpy.o -O3

.goto.bin:
    mips-linux-gnu-gcc-9 -c goto.S -o goto.o -O3

all: .print.bin .memcpy.bin .goto.bin
    mips-linux-gnu-gcc-9 \
        memcpy.o print.o goto.o \
        -o shellcode.elf \
        -nostdlib -Wl,--section-start=.text=0xbfc00000 -Wl,-Tshellcode_ldscript.ld
    objcopy -O binary -j .text -j .rodata shellcode.elf final_shellcode.bin

clean:
    rm -rf *.o
    rm -rf *.elf
    rm -rf *.bin
