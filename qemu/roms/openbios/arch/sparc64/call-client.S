	.globl	sparc64_of_client_interface

	.data
	.align	8
client_globals:
	.skip 64

	.text
	.align	4
        .register %g2, #scratch
        .register %g3, #scratch
        .register %g6, #scratch
        .register %g7, #scratch
/*
	make some more space on stack since linux kernel only provides 128 bytes
	without memory to spill registers (used by gcc in -O0 mode)
*/

sparc64_of_client_interface:
	/* make sure caller's windows are on caller's stack */
	flushw
	save %sp, -248, %sp
	stx	    %g1, [%sp + 2047 + 192 +  0]
	stx	    %g2, [%sp + 2047 + 192 +  8]
	stx	    %g3, [%sp + 2047 + 192 + 16]
	stx	    %g4, [%sp + 2047 + 192 + 24]
	stx	    %g5, [%sp + 2047 + 192 + 32]
	stx	    %g6, [%sp + 2047 + 192 + 40]
	stx	    %g7, [%sp + 2047 + 192 + 48]

	call of_client_interface
	 mov %i0, %o0
	mov %o0, %i0

	ldx	    [%sp + 2047 + 192 +  0], %g1
	ldx	    [%sp + 2047 + 192 +  8], %g2
	ldx	    [%sp + 2047 + 192 + 16], %g3
	ldx	    [%sp + 2047 + 192 + 24], %g4
	ldx	    [%sp + 2047 + 192 + 32], %g5
	ldx	    [%sp + 2047 + 192 + 40], %g6
	ldx	    [%sp + 2047 + 192 + 48], %g7
	return  %i7+8
	 nop

