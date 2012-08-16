/*
	Copyright (C) 2000, Entity Cyber, Inc.

	Authors: Gary Byers (gb@thinguin.org)
		 Marty Connor (mdc@thinguin.org)

	This software may be used and distributed according to the terms
	of the GNU Public License (GPL), incorporated herein by reference.

	Description:	

	This is just a little bit of code and data that can get prepended
	to a ROM image in order to allow bootloaders to load the result
	as if it were a Linux kernel image.

	A real Linux kernel image consists of a one-sector boot loader
	(to load the image from a floppy disk), followed a few sectors
	of setup code, followed by the kernel code itself.  There's
	a table in the first sector (starting at offset 497) that indicates
	how many sectors of setup code follow the first sector and which
	contains some other parameters that aren't interesting in this
	case.

	When a bootloader loads the sectors that comprise a kernel image,
	it doesn't execute the code in the first sector (since that code
	would try to load the image from a floppy disk.)  The code in the
	first sector below doesn't expect to get executed (and prints an
	error message if it ever -is- executed.)

	We don't require much in the way of setup code.  Historically, the
	Linux kernel required at least 4 sectors of setup code.
	Therefore, at least 4 sectors must be present even though we don't
	use them.

*/

FILE_LICENCE ( GPL_ANY )

#define	SETUPSECS 4		/* Minimal nr of setup-sectors */
#define PREFIXSIZE ((SETUPSECS+1)*512)
#define PREFIXPGH (PREFIXSIZE / 16 )
#define	BOOTSEG  0x07C0		/* original address of boot-sector */
#define	INITSEG  0x9000		/* we move boot here - out of the way */
#define	SETUPSEG 0x9020		/* setup starts here */
#define SYSSEG   0x1000		/* system loaded at 0x10000 (65536). */

	.text
	.code16
	.arch i386
	.org	0
	.section ".prefix", "ax", @progbits
	.globl	_lkrn_start
_lkrn_start:
/* 
	This is a minimal boot sector.	If anyone tries to execute it (e.g., if
	a .lilo file is dd'ed to a floppy), print an error message. 
*/

bootsector: 
	jmp	$BOOTSEG, $1f	/* reload cs:ip to match relocation addr */
1:
	movw	$0x2000, %di		/*  0x2000 is arbitrary value >= length
					    of bootsect + room for stack */

	movw	$BOOTSEG, %ax
	movw	%ax,%ds
	movw	%ax,%es

	cli
	movw	%ax, %ss		/* put stack at BOOTSEG:0x2000. */
	movw	%di,%sp
	sti

	movw	$why_end-why, %cx
	movw	$why, %si

	movw	$0x0007, %bx		/* page 0, attribute 7 (normal) */
	movb	$0x0e, %ah		/* write char, tty mode */
prloop: 
	lodsb
	int	$0x10
	loop	prloop
freeze: jmp	freeze

why:	.ascii	"This image cannot be loaded from a floppy disk.\r\n"
why_end: 


/*
	The following header is documented in the Linux source code at
	Documentation/x86/boot.txt
*/
	.org	497
setup_sects: 
	.byte	SETUPSECS
root_flags: 
	.word	0
syssize: 
	.long	-PREFIXPGH

	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADDL"
	.long	syssize
	.long	16
	.long	0
	.previous
	
ram_size: 
	.word	0
vid_mode: 
	.word	0
root_dev: 
	.word	0
boot_flag: 
	.word	0xAA55
jump:
	/* Manually specify a two-byte jmp instruction here rather
	 * than leaving it up to the assembler. */
	.byte	0xeb
	.byte	setup_code - header
header:
	.byte	'H', 'd', 'r', 'S'
version:
	.word	0x0207 /* 2.07 */
realmode_swtch:
	.long	0
start_sys:
	.word	0
kernel_version:
	.word	0
type_of_loader:
	.byte	0
loadflags:
	.byte	0
setup_move_size:
	.word	0
code32_start:
	.long	0
ramdisk_image:
	.long	0
ramdisk_size:
	.long	0
bootsect_kludge:
	.long	0
heap_end_ptr:
	.word	0
pad1:
	.word	0
cmd_line_ptr:
	.long	0
initrd_addr_max:
	/* We don't use an initrd but some bootloaders (e.g. SYSLINUX) have
	 * been known to require this field.  Set the value to 2 GB.  This
	 * value is also used by the Linux kernel. */
	.long	0x7fffffff
kernel_alignment:
	.long	0
relocatable_kernel:
	.byte	0
pad2:
	.byte	0, 0, 0
cmdline_size:
	.long	0
hardware_subarch:
	.long	0
hardware_subarch_data:
	.byte	0, 0, 0, 0, 0, 0, 0, 0

/*
	We don't need to do too much setup.

	This code gets loaded at SETUPSEG:0.  It wants to start
	executing the image that's loaded at SYSSEG:0 and
	whose entry point is SYSSEG:0.
*/
setup_code:
	/* We expect to be contiguous in memory once loaded.  The Linux image
	 * boot process requires that setup code is loaded separately from
	 * "non-real code".  Since we don't need any information that's left
	 * in the prefix, it doesn't matter: we just have to ensure that
	 * %cs:0000 is where the start of the image *would* be.
	 */
	ljmp	$(SYSSEG-(PREFIXSIZE/16)), $run_ipxe


	.org	PREFIXSIZE
/*
	We're now at the beginning of the kernel proper.
 */
run_ipxe:
	/* Set up stack just below 0x7c00 */
	xorw	%ax, %ax
	movw	%ax, %ss
	movw	$0x7c00, %sp

	/* Retrieve command-line pointer */
	movl	%es:cmd_line_ptr, %edx

	/* Install iPXE */
	call	install

	/* Set up real-mode stack */
	movw	%bx, %ss
	movw	$_estack16, %sp

	/* Jump to .text16 segment */
	pushw	%ax
	pushw	$1f
	lret
	.section ".text16", "awx", @progbits
1:
	/* Set up %ds for access to .data16 */
	movw	%bx, %ds

	/* Store command-line pointer */
	movl	%edx, cmdline_phys

	/* Run iPXE */
	pushl	$main
	pushw	%cs
	call	prot_call
	popl	%ecx /* discard */

	/* Uninstall iPXE */
	call	uninstall

	/* Boot next device */
	int $0x18
