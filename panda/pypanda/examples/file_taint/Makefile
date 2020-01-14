all: taint taint_asm

CFLAGS += -g  -O0

taint: taint.c
	$(CC) $(CFLAGS) -o $@ $<

taint_asm: taint.s
	nasm -f elf64 -F dwarf -g taint.s -o taint_asm.o
	ld -m elf_x86_64 -o taint_asm taint_asm.o

clean:
	rm -f taint taint_asm
