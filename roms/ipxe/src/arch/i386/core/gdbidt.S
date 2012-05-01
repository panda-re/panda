/*
 * Interrupt Descriptor Table (IDT) setup and interrupt handlers for GDB stub.
 */

#include <librm.h>

#define SIZEOF_I386_REGS	32
#define SIZEOF_I386_FLAGS	4

/****************************************************************************
 * Interrupt Descriptor Table
 ****************************************************************************
 */
	.section ".data16", "aw", @progbits
	.globl idtr
idtr:
idt_limit:
	.word	idt_length - 1
idt_base:
	.long	0

/* IDT entries have the following format:
 * offset_lo, segment selector, flags, offset_hi
 *
 * Since it is not possible to specify relocations in arbitrary
 * expressions like (int_overflow & 0xffff), we initialise the
 * IDT with entries in an incorrect format.
 *
 * The entries are shuffled into the correct format in init_librm().
 */
#define IDT_ENTRY_EMPTY(name) .word 0, 0, 0, 0
#define IDT_ENTRY_PRESENT(name) \
	.long	int_##name; \
	.word	0x8e00, VIRTUAL_CS

.align 16
idt:
	IDT_ENTRY_PRESENT(divide_error)
	IDT_ENTRY_PRESENT(debug_trap)
	IDT_ENTRY_EMPTY(non_maskable_interrupt)
	IDT_ENTRY_PRESENT(breakpoint)
	IDT_ENTRY_PRESENT(overflow)
	IDT_ENTRY_PRESENT(bound_range_exceeded)
	IDT_ENTRY_PRESENT(invalid_opcode)
	IDT_ENTRY_EMPTY(device_not_available)
	IDT_ENTRY_PRESENT(double_fault)
	IDT_ENTRY_EMPTY(coprocessor_segment_overrun)
	IDT_ENTRY_PRESENT(invalid_tss)
	IDT_ENTRY_PRESENT(segment_not_present)
	IDT_ENTRY_PRESENT(stack_segment_fault)
	IDT_ENTRY_PRESENT(general_protection)
	IDT_ENTRY_PRESENT(page_fault)
idt_end:
	.equ	idt_length, idt_end - idt

/* The IDT entries are fixed up (once) in init_librm() */
idt_fixed:
	.byte	0

/****************************************************************************
 * idt_init (real-mode near call, 16-bit real-mode near return address)
 *
 * Initialise the IDT, called from init_librm.
 *
 * Parameters:
 *   %eax : IDT base address
 *
 * Destroys %ax, %bx, and %di.
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.code16
	.globl idt_init
idt_init:
	movl	%eax, idt_base
	addl	$idt, idt_base

	/* IDT entries are only fixed up once */
	movb	idt_fixed, %al
	orb	%al, %al
	jnz	2f
	movb	$1, idt_fixed

	/* Shuffle IDT entries into the correct format */
	movb	$(idt_length / 8), %al
	movw	$idt, %bx
	or	%al, %al
	jz	2f
1:
	movw	2(%bx), %di
	xchg	%di, 6(%bx)
	movw	%di, 2(%bx)
	addw	$8, %bx
	dec	%al
	jnz	1b
2:
	ret

/****************************************************************************
 * Interrupt handlers
 ****************************************************************************
 */
	.section ".text", "ax", @progbits
	.code32

/* POSIX signal numbers for reporting traps to GDB */
#define SIGILL 4
#define SIGTRAP 5
#define SIGBUS 7
#define SIGFPE 8
#define SIGSEGV 11
#define SIGSTKFLT 16

int_divide_error:
	pushl	$SIGFPE
	jmp	do_interrupt

int_debug_trap:
int_breakpoint:
	pushl	$SIGTRAP
	jmp	do_interrupt

int_overflow:
int_bound_range_exceeded:
	pushl	$SIGSTKFLT
	jmp	do_interrupt

int_invalid_opcode:
	pushl	$SIGILL
	jmp	do_interrupt

int_double_fault:
	movl	$SIGBUS, (%esp)
	jmp	do_interrupt

int_invalid_tss:
int_segment_not_present:
int_stack_segment_fault:
int_general_protection:
int_page_fault:
	movl	$SIGSEGV, (%esp)
	jmp	do_interrupt

/* When invoked, the stack contains: eflags, cs, eip, signo. */
#define IH_OFFSET_GDB_REGS ( 0 )
#define IH_OFFSET_GDB_EIP ( IH_OFFSET_GDB_REGS + SIZEOF_I386_REGS )
#define IH_OFFSET_GDB_EFLAGS ( IH_OFFSET_GDB_EIP + 4 )
#define IH_OFFSET_GDB_SEG_REGS ( IH_OFFSET_GDB_EFLAGS + SIZEOF_I386_FLAGS )
#define IH_OFFSET_GDB_END ( IH_OFFSET_GDB_SEG_REGS + 6 * 4 )
#define IH_OFFSET_SIGNO ( IH_OFFSET_GDB_END )
#define IH_OFFSET_OLD_EIP ( IH_OFFSET_SIGNO + 4 )
#define IH_OFFSET_OLD_CS ( IH_OFFSET_OLD_EIP + 4 )
#define IH_OFFSET_OLD_EFLAGS ( IH_OFFSET_OLD_CS + 4 )
#define IH_OFFSET_END ( IH_OFFSET_OLD_EFLAGS + 4 )

/* We also access the stack whilst still storing or restoring
 * the register snapshot.  Since ESP is in flux, we need
 * special offsets.
 */
#define IH_OFFSET_FLUX_OLD_CS ( IH_OFFSET_OLD_CS - 44 )
#define IH_OFFSET_FLUX_OLD_EFLAGS ( IH_OFFSET_OLD_EFLAGS - 40 )
#define IH_OFFSET_FLUX_OLD_EIP ( IH_OFFSET_OLD_EIP - 36 )
#define IH_OFFSET_FLUX_END ( IH_OFFSET_END - 20 )
do_interrupt:
	/* Store CPU state in GDB register snapshot */
	pushw	$0
	pushw	%gs
	pushw	$0
	pushw	%fs
	pushw	$0
	pushw	%es
	pushw	$0
	pushw	%ds
	pushw	$0
	pushw	%ss
	pushw	$0
	pushw	IH_OFFSET_FLUX_OLD_CS + 2(%esp)
	pushl	IH_OFFSET_FLUX_OLD_EFLAGS(%esp)
	pushl	IH_OFFSET_FLUX_OLD_EIP(%esp)
	pushl	%edi
	pushl	%esi
	pushl	%ebp
	leal	IH_OFFSET_FLUX_END(%esp), %edi
	pushl	%edi /* old ESP */
	pushl	%ebx
	pushl	%edx
	pushl	%ecx
	pushl	%eax

	/* Call GDB stub exception handler */
	pushl	%esp
	pushl	(IH_OFFSET_SIGNO + 4)(%esp)
	call	gdbmach_handler
	addl	$8, %esp

	/* Restore CPU state from GDB register snapshot */
	popl	%eax
	popl	%ecx
	popl	%edx
	popl	%ebx
	addl	$4, %esp /* Changing ESP currently not supported */
	popl	%ebp
	popl	%esi
	popl	%edi
	popl	IH_OFFSET_FLUX_OLD_EIP(%esp)
	popl	IH_OFFSET_FLUX_OLD_EFLAGS(%esp)
	popl	IH_OFFSET_FLUX_OLD_CS(%esp)
	popl	%ss
	popl	%ds
	popl	%es
	popl	%fs
	popl	%gs

	addl	$4, %esp /* drop signo */
	iret
