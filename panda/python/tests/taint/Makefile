all: taint taint_asm

CFLAGS += -m32 -g -O0 -static

taint: taint.c
	$(CC) $(CFLAGS) -o $@ $<

taint_asm: taint.s
	nasm -f elf -F dwarf -g taint.s -o taint_asm.o
	ld -m elf_i386 -o taint_asm taint_asm.o

clean:
	rm -f taint taint_asm
