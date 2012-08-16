// Rom layout and bios assembler to C interface.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.


/****************************************************************
 * Include of 16bit C code
 ****************************************************************/

        .code16gcc
#include "ccode.16.s"

#include "config.h" // CONFIG_*
#include "ioport.h" // PORT_A20
#include "bregs.h" // CR0_*
#include "cmos.h" // CMOS_RESET_CODE
#include "asm-offsets.h" // BREGS_*
#include "entryfuncs.S" // ENTRY_*


/****************************************************************
 * Call trampolines
 ****************************************************************/

// Place CPU into 32bit mode from 16bit mode.
// %edx = return location (in 32bit mode)
// Clobbers: ecx, flags, segment registers, cr0, idt/gdt
        DECLFUNC transition32
transition32:
        movl %eax, %ecx

        // Disable irqs (and clear direction flag)
        cli
        cld

        // Disable nmi
        movl $CMOS_RESET_CODE|NMI_DISABLE_BIT, %eax
        outb %al, $PORT_CMOS_INDEX
        inb $PORT_CMOS_DATA, %al

        // enable a20
        inb $PORT_A20, %al
        orb $A20_ENABLE_BIT, %al
        outb %al, $PORT_A20

        // Set segment descriptors
        lidtw %cs:pmode_IDT_info
        lgdtw %cs:rombios32_gdt_48

        // Enable protected mode
        movl %cr0, %eax
        orl $CR0_PE, %eax
        movl %eax, %cr0

        // start 32bit protected mode code
        ljmpl $SEG32_MODE32_CS, $(BUILD_BIOS_ADDR + 1f)

        .code32
1:
        // init data segments
        movl $SEG32_MODE32_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %ss
        movw %ax, %fs
        movw %ax, %gs

        movl %ecx, %eax
        jmpl *%edx

// Place CPU into 16bit mode from 32bit mode.
// %edx = return location (in 16bit mode)
// Clobbers: ecx, flags, segment registers, cr0, idt/gdt
        DECLFUNC transition16
        .global transition16big
transition16:
        movl %eax, %ecx

        // restore data segment limits to 0xffff
        movl $SEG32_MODE16_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %ss
        movw %ax, %fs
        movw %ax, %gs

#if CONFIG_DISABLE_A20
        // disable a20
        inb $PORT_A20, %al
        andb $~A20_ENABLE_BIT, %al
        outb %al, $PORT_A20
#endif

        // Jump to 16bit mode
        ljmpw $SEG32_MODE16_CS, $1f

transition16big:
        movl %eax, %ecx

        movl $SEG32_MODE16BIG_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %ss
        movw %ax, %fs
        movw %ax, %gs

        ljmpw $SEG32_MODE16BIG_CS, $1f

        .code16gcc
1:
        // Disable protected mode
        movl %cr0, %eax
        andl $~CR0_PE, %eax
        movl %eax, %cr0

        // far jump to flush CPU queue after transition to real mode
        ljmpw $SEG_BIOS, $2f

2:
        // restore IDT to normal real-mode defaults
        lidtw %cs:rmode_IDT_info

        // Clear segment registers
        xorw %ax, %ax
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %es
        movw %ax, %ds
        movw %ax, %ss  // Assume stack is in segment 0

        movl %ecx, %eax
        jmpl *%edx

// Call a 16bit function from 16bit mode with a specified cpu register state
// %eax = address of struct bregs
// Clobbers: %e[bcd]x, %e[ds]i, flags
        DECLFUNC __call16
__call16:
        // Save %eax, %ebp
        pushl %ebp
        pushl %eax

        // Setup for iretw call
        pushw %cs
        pushw $1f               // return point
        pushw BREGS_flags(%eax) // flags
        pushl BREGS_code(%eax)  // CS:IP

        // Load calling registers.
        movl BREGS_edi(%eax), %edi
        movl BREGS_esi(%eax), %esi
        movl BREGS_ebp(%eax), %ebp
        movl BREGS_ebx(%eax), %ebx
        movl BREGS_edx(%eax), %edx
        movl BREGS_ecx(%eax), %ecx
        movw BREGS_es(%eax), %es
        movw BREGS_ds(%eax), %ds
        movl %ss:BREGS_eax(%eax), %eax

        // Invoke call
        iretw                   // XXX - just do a lcalll
1:
        // Store flags, eax, ecx
        pushfw
        pushl %eax
        movl 0x06(%esp), %eax
        movl %ecx, %ss:BREGS_ecx(%eax)
        movw %ds, %ss:BREGS_ds(%eax)
        movw %ss, %cx
        movw %cx, %ds           // Restore %ds == %ss
        popl %ecx
        movl %ecx, BREGS_eax(%eax)
        popw %cx
        movw %cx, BREGS_flags(%eax)

        // Store remaining registers
        movw %es, BREGS_es(%eax)
        movl %edi, BREGS_edi(%eax)
        movl %esi, BREGS_esi(%eax)
        movl %ebp, BREGS_ebp(%eax)
        movl %ebx, BREGS_ebx(%eax)
        movl %edx, BREGS_edx(%eax)

        // Remove %eax, restore %ebp
        popl %eax
        popl %ebp

        retl

// Call a 16bit function from 32bit mode.
// %eax = address of struct bregs
// Clobbers: %e[bcd]x, %e[ds]i, flags, segment registers, idt/gdt
        DECLFUNC __call16_from32
        .global __call16big_from32
        .code32
__call16_from32:
        movl $1f, %edx
        jmp transition16
__call16big_from32:
        movl $1f, %edx
        jmp transition16big

        // Make call.
        .code16gcc
1:      calll __call16
        // Return via transition32
        movl $(2f + BUILD_BIOS_ADDR), %edx
        jmp transition32
        .code32
2:      retl

        .code16gcc
// IRQ trampolines
        .macro IRQ_TRAMPOLINE num
        DECLFUNC irq_trampoline_0x\num
        irq_trampoline_0x\num :
        int $0x\num
        lretw
        .endm

        IRQ_TRAMPOLINE 10
        IRQ_TRAMPOLINE 13
        IRQ_TRAMPOLINE 15
        IRQ_TRAMPOLINE 16
        IRQ_TRAMPOLINE 18
        IRQ_TRAMPOLINE 19


/****************************************************************
 * Misc. entry points.
 ****************************************************************/

// Resume (and reboot) entry point - called from entry_post
        DECLFUNC entry_resume
entry_resume:
        // Disable interrupts
        cli
        cld
        // Use a stack in EBDA
        movw $SEG_BDA, %ax
        movw %ax, %ds
        movw BDA_ebda_seg, %ax
        movw %ax, %ds
        movw %ax, %ss
        movl $EBDA_OFFSET_TOP_STACK, %esp
        // Call handler.
        jmp handle_resume

// PMM entry point
        DECLFUNC entry_pmm
entry_pmm:
        pushl %esp              // Backup %esp, then clear high bits
        movzwl %sp, %esp
        pushfl                  // Save registers clobbered by C code
        cli
        cld
        pushl %eax
        pushl %ecx
        pushl %edx
        pushw %es
        pushw %ds
        movw %ss, %cx           // Move %ss to %ds
        movw %cx, %ds
        movl $_cfunc32flat_handle_pmm, %eax // Setup: call32(handle_pmm, args, -1)
        leal 28(%esp), %edx     // %edx points to start of args
        movl $-1, %ecx
        calll call32
        movw %ax, 12(%esp)      // Modify %ax:%dx to return %eax
        shrl $16, %eax
        movw %ax, 4(%esp)
        popw %ds                // Restore saved registers
        popw %es
        popl %edx
        popl %ecx
        popl %eax
        popfl
        popl %esp
        lretw

// PnP entry points
        DECLFUNC entry_pnp_real
        .global entry_pnp_prot
entry_pnp_prot:
        pushl %esp
        jmp 1f
entry_pnp_real:
        pushl %esp              // Backup %esp, then clear high bits
        movzwl %sp, %esp
1:
        pushfl                  // Save registers clobbered by C code
        cli
        cld
        pushl %eax
        pushl %ecx
        pushl %edx
        pushw %es
        pushw %ds
        movw %ss, %cx           // Move %ss to %ds
        movw %cx, %ds
        leal 28(%esp), %eax     // %eax points to start of u16 args
        calll handle_pnp
        movw %ax, 12(%esp)      // Modify %eax to return %ax
        popw %ds
        popw %es
        popl %edx
        popl %ecx
        popl %eax
        popfl
        popl %esp
        lretw

// APM entry points
        DECLFUNC entry_apm16
entry_apm16:
        pushfw          // save flags
        pushl %eax      // dummy
        ENTRY_ARG handle_apm16
        addw $4, %sp    // pop dummy
        popfw           // restore flags
        lretw

        .code32
        DECLFUNC entry_apm32
entry_apm32:
        pushfl
        pushl %gs
        pushl %cs               // Move second descriptor after %cs to %gs
        addl $16, (%esp)
        popl %gs
        ENTRY_ARG_ESP _cfunc32seg_handle_apm32
        popl %gs
        popfl
        lretl

// PCI-BIOS 32bit entry point
        DECLFUNC entry_pcibios32
entry_pcibios32:
        pushfl
        pushl %gs               // Backup %gs and set %gs=%ds
        pushl %ds
        popl %gs
        ENTRY_ARG_ESP _cfunc32seg_handle_pcibios32
        popl %gs
        popfl
        lretl

// BIOS32 support
        EXPORTFUNC entry_bios32
entry_bios32:
        pushfl
#if CONFIG_PCIBIOS
        // Check for PCI-BIOS request
        cmpl $0x49435024, %eax // $PCI
        jne 1f
        movl $BUILD_BIOS_ADDR, %ebx
        movl $BUILD_BIOS_SIZE, %ecx
        movl $entry_pcibios32, %edx
        xorb %al, %al
        jmp 2f
#endif
        // Unknown request
1:      movb $0x80, %al
        // Return to caller
2:      popfl
        lretl

// 32bit elf entry point
        EXPORTFUNC entry_elf
entry_elf:
        cli
        cld
        lidtl (BUILD_BIOS_ADDR + pmode_IDT_info)
        lgdtl (BUILD_BIOS_ADDR + rombios32_gdt_48)
        movl $SEG32_MODE32_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss
        movl $BUILD_STACK_ADDR, %esp
        ljmpl $SEG32_MODE32_CS, $_cfunc32flat_handle_post

        .code16gcc


/****************************************************************
 * Interrupt entry points
 ****************************************************************/

        // Main entry point for interrupts without args
        DECLFUNC irqentry
irqentry:
        ENTRY_ST
        iretw

        // Main entry point for interrupts with args
        DECLFUNC irqentryarg
irqentryarg:
        ENTRY_ARG_ST
        iretw

        // Define an entry point for an interrupt (no args passed).
        .macro IRQ_ENTRY num
        .global entry_\num
        entry_\num :
        pushl $ handle_\num
        jmp irqentry
        .endm

        .macro DECL_IRQ_ENTRY num
        DECLFUNC entry_\num
        IRQ_ENTRY \num
        .endm

        // Define an entry point for an interrupt (can read/modify args).
        .macro IRQ_ENTRY_ARG num
        .global entry_\num
        entry_\num :
        pushl $ handle_\num
        jmp irqentryarg
        .endm

        .macro DECL_IRQ_ENTRY_ARG num
        DECLFUNC entry_\num
        IRQ_ENTRY_ARG \num
        .endm

        // Various entry points (that don't require a fixed location).
        DECL_IRQ_ENTRY_ARG 13
        DECL_IRQ_ENTRY 76
        DECL_IRQ_ENTRY 70
        DECL_IRQ_ENTRY 74
        DECL_IRQ_ENTRY 75
        DECL_IRQ_ENTRY hwpic1
        DECL_IRQ_ENTRY hwpic2

        // int 18/19 are special - they reset stack and call into 32bit mode.
        DECLFUNC entry_19
entry_19:
        ENTRY_INTO32 _cfunc32flat_handle_19

        DECLFUNC entry_18
entry_18:
        ENTRY_INTO32 _cfunc32flat_handle_18


/****************************************************************
 * Fixed position entry points
 ****************************************************************/

        // Specify a location in the fixed part of bios area.
        .macro ORG addr
        .section .fixedaddr.\addr
        .endm

        ORG 0xe05b
entry_post:
        cmpl $0, %cs:HaveRunPost                // Check for resume/reboot
        jnz entry_resume
        ENTRY_INTO32 _cfunc32flat_handle_post   // Normal entry point

        ORG 0xe2c3
        IRQ_ENTRY 02

        ORG 0xe3fe
        .global entry_13_official
entry_13_official:
        jmp entry_13

        // 0xe401 - OldFDPT in disk.c

        ORG 0xe6f2
        .global entry_19_official
entry_19_official:
        jmp entry_19

        // 0xe6f5 - BIOS_CONFIG_TABLE in misc.c

        // 0xe729 - BaudTable in serial.c

        ORG 0xe739
        IRQ_ENTRY_ARG 14

        ORG 0xe82e
        IRQ_ENTRY_ARG 16

        ORG 0xe987
        IRQ_ENTRY 09

        ORG 0xec59
        IRQ_ENTRY_ARG 40

        ORG 0xef57
        IRQ_ENTRY 0e

        // 0xefc7 - diskette_param_table in floppy.c

        ORG 0xefd2
        IRQ_ENTRY_ARG 17

        ORG 0xf045
entry_10_0x0f:
        // XXX - INT 10 Functions 0-Fh Entry Point
        iretw

        ORG 0xf065
        IRQ_ENTRY_ARG 10

        // 0xf0a4 - VideoParams in misc.c

        ORG 0xf841
        IRQ_ENTRY_ARG 12

        ORG 0xf84d
        IRQ_ENTRY_ARG 11

        ORG 0xf859
        IRQ_ENTRY_ARG 15

        // 0xfa6e - vgafont8 in font.c

        ORG 0xfe6e
        IRQ_ENTRY_ARG 1a

        ORG 0xfea5
        IRQ_ENTRY 08

        // 0xfef3 - InitVectors in misc.c

        // 0xff00 - BiosCopyright in misc.c

        ORG 0xff53
        .global entry_iret_official
entry_iret_official:
        iretw

        ORG 0xff54
        IRQ_ENTRY_ARG 05

        ORG 0xfff0 // Power-up Entry Point
        .global reset_vector
reset_vector:
        ljmpw $SEG_BIOS, $entry_post

        // 0xfff5 - BiosDate in misc.c

        // 0xfffe - BiosModelId in misc.c

        // 0xffff - BiosChecksum in misc.c

        .end
