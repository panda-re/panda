// Code for handling calls to "post" that are resume related.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "ioport.h" // outb
#include "pic.h" // eoi_pic2
#include "biosvar.h" // struct bios_data_area_s
#include "bregs.h" // struct bregs
#include "acpi.h" // find_resume_vector
#include "ps2port.h" // i8042_reboot
#include "pci.h" // pci_reboot
#include "cmos.h" // inb_cmos

// Indicator if POST phase has been run.
int HaveRunPost VAR16VISIBLE;

// Reset DMA controller
void
init_dma(void)
{
    // first reset the DMA controllers
    outb(0, PORT_DMA1_MASTER_CLEAR);
    outb(0, PORT_DMA2_MASTER_CLEAR);

    // then initialize the DMA controllers
    outb(0xc0, PORT_DMA2_MODE_REG);
    outb(0x00, PORT_DMA2_MASK_REG);
}

// Handler for post calls that look like a resume.
void VISIBLE16
handle_resume(void)
{
    debug_serial_setup();
    int status = inb_cmos(CMOS_RESET_CODE);
    outb_cmos(0, CMOS_RESET_CODE);
    dprintf(1, "In resume (status=%d)\n", status);

    init_dma();

    switch (status) {
    case 0x01 ... 0x04:
    case 0x06 ... 0x09:
        panic("Unimplemented shutdown status: %02x\n", status);

    case 0x05:
        // flush keyboard (issue EOI) and jump via 40h:0067h
        eoi_pic2();
        // NO BREAK
    case 0x0a:
#define BDA_JUMP (((struct bios_data_area_s *)0)->jump)
        // resume execution by jump via 40h:0067h
        asm volatile(
            "movw %w1, %%ds\n"
            "ljmpw *%0\n"
            : : "m"(BDA_JUMP), "r"(SEG_BDA)
            );
        break;

    case 0x0b:
        // resume execution via IRET via 40h:0067h
        asm volatile(
            "movw %w1, %%ds\n"
            "lssw %0, %%sp\n"
            "iretw\n"
            : : "m"(BDA_JUMP), "r"(SEG_BDA)
            );
        break;

    case 0x0c:
        // resume execution via RETF via 40h:0067h
        asm volatile(
            "movw %w1, %%ds\n"
            "lssw %0, %%sp\n"
            "lretw\n"
            : : "m"(BDA_JUMP), "r"(SEG_BDA)
            );
        break;

    default:
        break;
    }

    // Not a 16bit resume - do remaining checks in 32bit mode
    asm volatile(
        "movw %w1, %%ss\n"
        "movl %0, %%esp\n"
        "movl $_cfunc32flat_handle_resume32, %%edx\n"
        "jmp transition32\n"
        : : "i"(BUILD_S3RESUME_STACK_ADDR), "r"(0), "a"(status)
        );
}

// Handle an S3 resume event
static void
s3_resume(void)
{
    if (!CONFIG_S3_RESUME)
        return;

    u32 s3_resume_vector = find_resume_vector();
    if (!s3_resume_vector) {
        dprintf(1, "No resume vector set!\n");
        return;
    }

    smm_init();

    s3_resume_vga_init();

    make_bios_readonly();

    // Invoke the resume vector.
    struct bregs br;
    memset(&br, 0, sizeof(br));
    dprintf(1, "Jump to resume vector (%x)\n", s3_resume_vector);
    br.code = FLATPTR_TO_SEGOFF((void*)s3_resume_vector);
    call16big(&br);
}

// Attempt to invoke a hard-reboot.
static void
tryReboot(void)
{
    dprintf(1, "Attempting a hard reboot\n");

    // Setup for reset on qemu.
    if (! CONFIG_COREBOOT) {
        qemu_prep_reset();
        if (HaveRunPost)
            apm_shutdown();
    }

    // Try keyboard controller reboot.
    i8042_reboot();

    // Try PCI 0xcf9 reboot
    pci_reboot();

    // Try triple fault
    asm volatile("int3");

    panic("Could not reboot");
}

void VISIBLE32FLAT
handle_resume32(int status)
{
    ASSERT32FLAT();
    dprintf(1, "In 32bit resume\n");

    if (status == 0xfe)
        s3_resume();

    // Must be a soft reboot - invoke a hard reboot.
    tryReboot();
}
