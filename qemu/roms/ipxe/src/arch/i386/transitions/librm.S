/*
 * librm: a library for interfacing to real-mode code
 *
 * Michael Brown <mbrown@fensystems.co.uk>
 *
 */

FILE_LICENCE ( GPL2_OR_LATER )

/* Drag in local definitions */
#include "librm.h"

/* For switches to/from protected mode */
#define CR0_PE 1

/* Size of various C data structures */
#define SIZEOF_I386_SEG_REGS	12
#define SIZEOF_I386_REGS	32
#define SIZEOF_REAL_MODE_REGS	( SIZEOF_I386_SEG_REGS + SIZEOF_I386_REGS )
#define SIZEOF_I386_FLAGS	4
#define SIZEOF_I386_ALL_REGS	( SIZEOF_REAL_MODE_REGS + SIZEOF_I386_FLAGS )
	
	.arch i386

/****************************************************************************
 * Global descriptor table
 *
 * Call init_librm to set up the GDT before attempting to use any
 * protected-mode code.
 *
 * NOTE: This must be located before prot_to_real, otherwise gas
 * throws a "can't handle non absolute segment in `ljmp'" error due to
 * not knowing the value of REAL_CS when the ljmp is encountered.
 *
 * Note also that putting ".word gdt_end - gdt - 1" directly into
 * gdt_limit, rather than going via gdt_length, will also produce the
 * "non absolute segment" error.  This is most probably a bug in gas.
 ****************************************************************************
 */
	.section ".data16", "aw", @progbits
	.align 16
gdt:
gdtr:		/* The first GDT entry is unused, the GDTR can fit here. */
gdt_limit:		.word gdt_length - 1
gdt_base:		.long 0
			.word 0 /* padding */

	.org	gdt + VIRTUAL_CS, 0
virtual_cs:	/* 32 bit protected mode code segment, virtual addresses */
	.word	0xffff, 0
	.byte	0, 0x9f, 0xcf, 0

	.org	gdt + VIRTUAL_DS, 0
virtual_ds:	/* 32 bit protected mode data segment, virtual addresses */
	.word	0xffff, 0
	.byte	0, 0x93, 0xcf, 0
	
	.org	gdt + PHYSICAL_CS, 0
physical_cs:	/* 32 bit protected mode code segment, physical addresses */
	.word	0xffff, 0
	.byte	0, 0x9f, 0xcf, 0

	.org	gdt + PHYSICAL_DS, 0
physical_ds:	/* 32 bit protected mode data segment, physical addresses */
	.word	0xffff, 0
	.byte	0, 0x93, 0xcf, 0	

	.org	gdt + REAL_CS, 0
real_cs: 	/* 16 bit flat real mode code segment */
	.word	0xffff, 0
	.byte	0, 0x9b, 0x8f, 0

	.org	gdt + REAL_DS	
real_ds:	/* 16 bit flat real mode data segment */
	.word	0xffff, 0
	.byte	0, 0x93, 0x8f, 0
	
gdt_end:
	.equ	gdt_length, gdt_end - gdt

/****************************************************************************
 * init_librm (real-mode far call, 16-bit real-mode far return address)
 *
 * Initialise the GDT ready for transitions to protected mode.
 *
 * Parameters:
 *   %cs : .text16 segment
 *   %ds : .data16 segment
 *   %edi : Physical base of protected-mode code (virt_offset)
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.code16
	.globl init_librm
init_librm:
	/* Preserve registers */
	pushl	%eax
	pushl	%ebx

	/* Store _virt_offset and set up virtual_cs and virtual_ds segments */
	movl	%edi, %eax
	movw	$virtual_cs, %bx
	call	set_seg_base
	movw	$virtual_ds, %bx
	call	set_seg_base	
	movl	%edi, _virt_offset

	/* Negate virt_offset */
	negl	%edi
		
	/* Store rm_cs and _text16, set up real_cs segment */
	xorl	%eax, %eax
	movw	%cs, %ax
	movw	%ax, rm_cs
	shll	$4, %eax
	movw	$real_cs, %bx
	call	set_seg_base
	addr32 leal	(%eax, %edi), %ebx
	movl	%ebx, _text16

	/* Store rm_ds and _data16, set up real_ds segment */
	xorl	%eax, %eax
	movw	%ds, %ax
	movw	%ax, %cs:rm_ds
	shll	$4, %eax
	movw	$real_ds, %bx
	call	set_seg_base
	addr32 leal	(%eax, %edi), %ebx
	movl	%ebx, _data16

	/* Set GDT and IDT base */
	movl	%eax, gdt_base
	addl	$gdt, gdt_base
	call	idt_init

	/* Restore registers */
	negl	%edi
	popl	%ebx
	popl	%eax
	lret

	.section ".text16", "ax", @progbits
	.code16
	.weak idt_init
set_seg_base:
1:	movw	%ax, 2(%bx)
	rorl	$16, %eax
	movb	%al, 4(%bx)
	movb	%ah, 7(%bx)
	roll	$16, %eax
idt_init: /* Reuse the return opcode here */
	ret

/****************************************************************************
 * real_to_prot (real-mode near call, 32-bit virtual return address)
 *
 * Switch from 16-bit real-mode to 32-bit protected mode with virtual
 * addresses.  The real-mode %ss:sp is stored in rm_ss and rm_sp, and
 * the protected-mode %esp is restored from the saved pm_esp.
 * Interrupts are disabled.  All other registers may be destroyed.
 *
 * The return address for this function should be a 32-bit virtual
 * address.
 *
 * Parameters: 
 *   %ecx : number of bytes to move from RM stack to PM stack
 *
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.code16
real_to_prot:
	/* Enable A20 line */
	call	enable_a20
	/* A failure at this point is fatal, and there's nothing we
	 * can do about it other than lock the machine to make the
	 * problem immediately visible.
	 */
1:	jc	1b

	/* Make sure we have our data segment available */
	movw	%cs:rm_ds, %ax
	movw	%ax, %ds

	/* Add _virt_offset, _text16 and _data16 to stack to be
	 * copied, and also copy the return address.
	 */
	pushl	_virt_offset
	pushl	_text16
	pushl	_data16
	addw	$16, %cx /* %ecx must be less than 64kB anyway */

	/* Real-mode %ss:%sp => %ebp:%edx and virtual address => %esi */
	xorl	%ebp, %ebp
	movw	%ss, %bp
	movzwl	%sp, %edx
	movl	%ebp, %eax
	shll	$4, %eax
	addr32 leal (%eax,%edx), %esi
	subl	_virt_offset, %esi

	/* Switch to protected mode */
	cli
	data32 lgdt gdtr
	data32 lidt idtr
	movl	%cr0, %eax
	orb	$CR0_PE, %al
	movl	%eax, %cr0
	data32 ljmp	$VIRTUAL_CS, $1f
	.section ".text", "ax", @progbits
	.code32
1:
	/* Set up protected-mode data segments and stack pointer */
	movw	$VIRTUAL_DS, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss
	movl	pm_esp, %esp

	/* Record real-mode %ss:sp (after removal of data) */
	movw	%bp, rm_ss
	addl	%ecx, %edx
	movw	%dx, rm_sp

	/* Move data from RM stack to PM stack */
	subl	%ecx, %esp
	movl	%esp, %edi
	rep movsb

	/* Publish virt_offset, text16 and data16 for PM code to use */
	popl	data16
	popl	text16
	popl	virt_offset

	/* Return to virtual address */
	ret

	/* Default IDTR with no interrupts */
	.section ".data16", "aw", @progbits
	.weak idtr
idtr:
rm_idtr:
	.word 0xffff /* limit */
	.long 0 /* base */

/****************************************************************************
 * prot_to_real (protected-mode near call, 32-bit real-mode return address)
 *
 * Switch from 32-bit protected mode with virtual addresses to 16-bit
 * real mode.  The protected-mode %esp is stored in pm_esp and the
 * real-mode %ss:sp is restored from the saved rm_ss and rm_sp.  The
 * high word of the real-mode %esp is set to zero.  All real-mode data
 * segment registers are loaded from the saved rm_ds.  Interrupts are
 * *not* enabled, since we want to be able to use prot_to_real in an
 * ISR.  All other registers may be destroyed.
 *
 * The return address for this function should be a 32-bit (sic)
 * real-mode offset within .code16.
 *
 * Parameters: 
 *   %ecx : number of bytes to move from PM stack to RM stack
 *
 ****************************************************************************
 */
	.section ".text", "ax", @progbits
	.code32
prot_to_real:
	/* Add return address to data to be moved to RM stack */
	addl	$4, %ecx
	
	/* Real-mode %ss:sp => %ebp:edx and virtual address => %edi */
	movzwl	rm_ss, %ebp
	movzwl	rm_sp, %edx
	subl	%ecx, %edx
	movl	%ebp, %eax
	shll	$4, %eax
	leal	(%eax,%edx), %edi
	subl	virt_offset, %edi
	
	/* Move data from PM stack to RM stack */
	movl	%esp, %esi
	rep movsb
	
	/* Record protected-mode %esp (after removal of data) */
	movl	%esi, pm_esp

	/* Load real-mode segment limits */
	movw	$REAL_DS, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss
	ljmp	$REAL_CS, $1f
	.section ".text16", "ax", @progbits
	.code16
1:
	/* Switch to real mode */
	movl	%cr0, %eax
	andb	$0!CR0_PE, %al
	movl	%eax, %cr0
	ljmp	*p2r_jump_vector
p2r_jump_target:

	/* Set up real-mode data segments and stack pointer */
	movw	%cs:rm_ds, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%bp, %ss
	movl	%edx, %esp

	/* Reset IDTR to the real-mode defaults */
	data32 lidt rm_idtr

	/* Return to real-mode address */
	data32 ret


	/* Real-mode code and data segments.  Assigned by the call to
	 * init_librm.  rm_cs doubles as the segment part of the jump
	 * vector used by prot_to_real.  rm_ds is located in .text16
	 * rather than .data16 because code needs to be able to locate
	 * the data segment.
	 */
	.section ".data16", "aw", @progbits
p2r_jump_vector:
	.word	p2r_jump_target
	.globl rm_cs
rm_cs:	.word 0
	.globl rm_ds
	.section ".text16.data", "aw", @progbits
rm_ds:	.word 0

/****************************************************************************
 * prot_call (real-mode far call, 16-bit real-mode far return address)
 *
 * Call a specific C function in the protected-mode code.  The
 * prototype of the C function must be
 *   void function ( struct i386_all_regs *ix86 ); 
 * ix86 will point to a struct containing the real-mode registers
 * at entry to prot_call.  
 *
 * All registers will be preserved across prot_call(), unless the C
 * function explicitly overwrites values in ix86.  Interrupt status
 * and GDT will also be preserved.  Gate A20 will be enabled.
 *
 * Note that prot_call() does not rely on the real-mode stack
 * remaining intact in order to return, since everything relevant is
 * copied to the protected-mode stack for the duration of the call.
 * In particular, this means that a real-mode prefix can make a call
 * to main() which will return correctly even if the prefix's stack
 * gets vapourised during the Etherboot run.  (The prefix cannot rely
 * on anything else on the stack being preserved, so should move any
 * critical data to registers before calling main()).
 *
 * Parameters:
 *   function : virtual address of protected-mode function to call
 *
 * Example usage:
 *	pushl	$pxe_api_call
 *	call	prot_call
 *	addw	$4, %sp
 * to call in to the C function
 *      void pxe_api_call ( struct i386_all_regs *ix86 );
 ****************************************************************************
 */

#define PC_OFFSET_GDT ( 0 )
#define PC_OFFSET_IDT ( PC_OFFSET_GDT + 8 /* pad to 8 to keep alignment */ )
#define PC_OFFSET_IX86 ( PC_OFFSET_IDT + 8 /* pad to 8 to keep alignment */ )
#define PC_OFFSET_RETADDR ( PC_OFFSET_IX86 + SIZEOF_I386_ALL_REGS )
#define PC_OFFSET_FUNCTION ( PC_OFFSET_RETADDR + 4 )
#define PC_OFFSET_END ( PC_OFFSET_FUNCTION + 4 )

	.section ".text16", "ax", @progbits
	.code16
	.globl prot_call
prot_call:
	/* Preserve registers, flags and GDT on external RM stack */
	pushfl
	pushal
	pushw	%gs
	pushw	%fs
	pushw	%es
	pushw	%ds
	pushw	%ss
	pushw	%cs
	subw	$16, %sp
	movw	%sp, %bp
	sidt	8(%bp)
	sgdt	(%bp)

	/* For sanity's sake, clear the direction flag as soon as possible */
	cld

	/* Switch to protected mode and move register dump to PM stack */
	movl	$PC_OFFSET_END, %ecx
	pushl	$1f
	jmp	real_to_prot
	.section ".text", "ax", @progbits
	.code32
1:
	/* Call function */
	leal	PC_OFFSET_IX86(%esp), %eax
	pushl	%eax
	call	*(PC_OFFSET_FUNCTION+4)(%esp)
	popl	%eax /* discard */

	/* Switch to real mode and move register dump back to RM stack */
	movl	$PC_OFFSET_END, %ecx
	pushl	$1f
	jmp	prot_to_real
	.section ".text16", "ax", @progbits
	.code16
1:	
	/* Reload GDT and IDT, restore registers and flags and return */
	movw	%sp, %bp
	data32 lgdt (%bp)
	data32 lidt 8(%bp)
	addw	$20, %sp /* also skip %cs and %ss */
	popw	%ds
	popw	%es
	popw	%fs
	popw	%gs
	popal
	/* popal skips %esp.  We therefore want to do "movl -20(%sp),
	 * %esp", but -20(%sp) is not a valid 80386 expression.
	 * Fortunately, prot_to_real() zeroes the high word of %esp, so
	 * we can just use -20(%esp) instead.
	 */
	addr32 movl -20(%esp), %esp
	popfl
	lret

/****************************************************************************
 * real_call (protected-mode near call, 32-bit virtual return address)
 *
 * Call a real-mode function from protected-mode code.
 *
 * The non-segment register values will be passed directly to the
 * real-mode code.  The segment registers will be set as per
 * prot_to_real.  The non-segment register values set by the real-mode
 * function will be passed back to the protected-mode caller.  A
 * result of this is that this routine cannot be called directly from
 * C code, since it clobbers registers that the C ABI expects the
 * callee to preserve.
 *
 * librm.h defines a convenient macro REAL_CODE() for using real_call.
 * See librm.h and realmode.h for details and examples.
 *
 * Parameters:
 *   (32-bit) near pointer to real-mode function to call
 *
 * Returns: none
 ****************************************************************************
 */

#define RC_OFFSET_PRESERVE_REGS ( 0 )
#define RC_OFFSET_RETADDR ( RC_OFFSET_PRESERVE_REGS + SIZEOF_I386_REGS )
#define RC_OFFSET_FUNCTION ( RC_OFFSET_RETADDR + 4 )
#define RC_OFFSET_END ( RC_OFFSET_FUNCTION + 4 )

	.section ".text", "ax", @progbits
	.code32
	.globl real_call
real_call:
	/* Create register dump and function pointer copy on PM stack */
	pushal
	pushl	RC_OFFSET_FUNCTION(%esp)

	/* Switch to real mode and move register dump to RM stack  */
	movl	$( RC_OFFSET_RETADDR + 4 /* function pointer copy */ ), %ecx
	pushl	$1f
	jmp	prot_to_real
	.section ".text16", "ax", @progbits
	.code16
1:
	/* Call real-mode function */
	popl	rc_function
	popal
	call	*rc_function
	pushal

	/* For sanity's sake, clear the direction flag as soon as possible */
	cld

	/* Switch to protected mode and move register dump back to PM stack */
	movl	$RC_OFFSET_RETADDR, %ecx
	pushl	$1f
	jmp	real_to_prot
	.section ".text", "ax", @progbits
	.code32
1:
	/* Restore registers and return */
	popal
	ret


	/* Function vector, used because "call xx(%sp)" is not a valid
	 * 16-bit expression.
	 */
	.section ".data16", "aw", @progbits
rc_function:	.word 0, 0

/****************************************************************************
 * Stored real-mode and protected-mode stack pointers
 *
 * The real-mode stack pointer is stored here whenever real_to_prot
 * is called and restored whenever prot_to_real is called.  The
 * converse happens for the protected-mode stack pointer.
 *
 * Despite initial appearances this scheme is, in fact re-entrant,
 * because program flow dictates that we always return via the point
 * we left by.  For example:
 *    PXE API call entry
 *  1   real => prot
 *        ...
 *        Print a text string
 *	    ...
 *  2       prot => real
 *            INT 10
 *  3       real => prot
 *	    ...
 *        ...
 *  4   prot => real
 *    PXE API call exit
 *
 * At point 1, the RM mode stack value, say RPXE, is stored in
 * rm_ss,sp.  We want this value to still be present in rm_ss,sp when
 * we reach point 4.
 *
 * At point 2, the RM stack value is restored from RPXE.  At point 3,
 * the RM stack value is again stored in rm_ss,sp.  This *does*
 * overwrite the RPXE that we have stored there, but it's the same
 * value, since the code between points 2 and 3 has managed to return
 * to us.
 ****************************************************************************
 */
	.section ".data", "aw", @progbits
	.globl rm_sp
rm_sp:	.word 0
	.globl rm_ss
rm_ss:	.word 0
pm_esp:	.long _estack

/****************************************************************************
 * Virtual address offsets
 *
 * These are used by the protected-mode code to map between virtual
 * and physical addresses, and to access variables in the .text16 or
 * .data16 segments.
 ****************************************************************************
 */
	/* Internal copies, created by init_librm (which runs in real mode) */
	.section ".data16", "aw", @progbits
_virt_offset:	.long 0
_text16:	.long 0
_data16:	.long 0

	/* Externally-visible copies, created by real_to_prot */
	.section ".data", "aw", @progbits
	.globl virt_offset
virt_offset:	.long 0	
	.globl text16
text16:		.long 0
	.globl data16
data16:		.long 0
