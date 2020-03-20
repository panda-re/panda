section .text
global _start
global taint_me
global query_taint
global do_exit

_start:
	xor eax, eax
  xor ebx, ebx
  jmp taint_me

taint_me:
  add eax, 5
  add ebx, eax
  add ecx, ebx
  jmp query_taint

query_taint:
  add ebx, 5
  jmp do_exit

do_exit:
    mov     eax, 1
    int     0x80
