// Code for misc 16bit handlers and variables.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "bregs.h" // struct bregs
#include "biosvar.h" // GET_BDA
#include "util.h" // debug_enter
#include "pic.h" // enable_hwirq

// Amount of continuous ram under 4Gig
u32 RamSize VAR16VISIBLE;
// Amount of continuous ram >4Gig
u64 RamSizeOver4G;
// Space for bios tables built an run-time.
char BiosTableSpace[CONFIG_MAX_BIOSTABLE] __aligned(MALLOC_MIN_ALIGN) VAR16VISIBLE;


/****************************************************************
 * Misc 16bit ISRs
 ****************************************************************/

// INT 12h Memory Size Service Entry Point
void VISIBLE16
handle_12(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_12);
    regs->ax = GET_BDA(mem_size_kb);
}

// INT 11h Equipment List Service Entry Point
void VISIBLE16
handle_11(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_11);
    regs->ax = GET_BDA(equipment_list_flags);
}

// INT 05h Print Screen Service Entry Point
void VISIBLE16
handle_05(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_05);
}

// INT 10h Video Support Service Entry Point
void VISIBLE16
handle_10(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_10);
    // dont do anything, since the VGA BIOS handles int10h requests
}

// NMI handler
void VISIBLE16
handle_02(void)
{
    debug_isr(DEBUG_ISR_02);
}

void
mathcp_setup(void)
{
    dprintf(3, "math cp init\n");
    // 80x87 coprocessor installed
    SETBITS_BDA(equipment_list_flags, 0x02);
    enable_hwirq(13, FUNC16(entry_75));
}

// INT 75 - IRQ13 - MATH COPROCESSOR EXCEPTION
void VISIBLE16
handle_75(void)
{
    debug_isr(DEBUG_ISR_75);

    // clear irq13
    outb(0, PORT_MATH_CLEAR);
    // clear interrupt
    eoi_pic2();
    // legacy nmi call
    u32 eax=0, flags;
    call16_simpint(0x02, &eax, &flags);
}


/****************************************************************
 * BIOS_CONFIG_TABLE
 ****************************************************************/

// DMA channel 3 used by hard disk BIOS
#define CBT_F1_DMA3USED (1<<7)
// 2nd interrupt controller (8259) installed
#define CBT_F1_2NDPIC   (1<<6)
// Real-Time Clock installed
#define CBT_F1_RTC      (1<<5)
// INT 15/AH=4Fh called upon INT 09h
#define CBT_F1_INT154F  (1<<4)
// wait for external event (INT 15/AH=41h) supported
#define CBT_F1_WAITEXT  (1<<3)
// extended BIOS area allocated (usually at top of RAM)
#define CBT_F1_EBDA     (1<<2)
// bus is Micro Channel instead of ISA
#define CBT_F1_MCA      (1<<1)
// system has dual bus (Micro Channel + ISA)
#define CBT_F1_MCAISA   (1<<0)

// INT 16/AH=09h (keyboard functionality) supported
#define CBT_F2_INT1609  (1<<6)

struct bios_config_table_s BIOS_CONFIG_TABLE VAR16FIXED(0xe6f5) = {
    .size     = sizeof(BIOS_CONFIG_TABLE) - 2,
    .model    = CONFIG_MODEL_ID,
    .submodel = CONFIG_SUBMODEL_ID,
    .biosrev  = CONFIG_BIOS_REVISION,
    .feature1 = (
        CBT_F1_2NDPIC | CBT_F1_RTC | CBT_F1_EBDA
        | (CONFIG_KBD_CALL_INT15_4F ? CBT_F1_INT154F : 0)),
    .feature2 = CBT_F2_INT1609,
    .feature3 = 0,
    .feature4 = 0,
    .feature5 = 0,
};


/****************************************************************
 * GDT and IDT tables
 ****************************************************************/

// Real mode IDT descriptor
struct descloc_s rmode_IDT_info VAR16VISIBLE = {
    .length = sizeof(struct rmode_IVT) - 1,
    .addr = (u32)MAKE_FLATPTR(SEG_IVT, 0),
};

// Dummy IDT that forces a machine shutdown if an irq happens in
// protected mode.
u8 dummy_IDT VAR16VISIBLE;

// Protected mode IDT descriptor
struct descloc_s pmode_IDT_info VAR16VISIBLE = {
    .length = sizeof(dummy_IDT) - 1,
    .addr = (u32)MAKE_FLATPTR(SEG_BIOS, &dummy_IDT),
};

// GDT
u64 rombios32_gdt[] VAR16VISIBLE __aligned(8) = {
    // First entry can't be used.
    0x0000000000000000LL,
    // 32 bit flat code segment (SEG32_MODE32_CS)
    GDT_GRANLIMIT(0xffffffff) | GDT_CODE | GDT_B,
    // 32 bit flat data segment (SEG32_MODE32_DS)
    GDT_GRANLIMIT(0xffffffff) | GDT_DATA | GDT_B,
    // 16 bit code segment base=0xf0000 limit=0xffff (SEG32_MODE16_CS)
    GDT_LIMIT(BUILD_BIOS_SIZE-1) | GDT_CODE | GDT_BASE(BUILD_BIOS_ADDR),
    // 16 bit data segment base=0x0 limit=0xffff (SEG32_MODE16_DS)
    GDT_LIMIT(0x0ffff) | GDT_DATA,
    // 16 bit code segment base=0xf0000 limit=0xffffffff (SEG32_MODE16BIG_CS)
    GDT_GRANLIMIT(0xffffffff) | GDT_CODE | GDT_BASE(BUILD_BIOS_ADDR),
    // 16 bit data segment base=0 limit=0xffffffff (SEG32_MODE16BIG_DS)
    GDT_GRANLIMIT(0xffffffff) | GDT_DATA,
};

// GDT descriptor
struct descloc_s rombios32_gdt_48 VAR16VISIBLE = {
    .length = sizeof(rombios32_gdt) - 1,
    .addr = (u32)MAKE_FLATPTR(SEG_BIOS, rombios32_gdt),
};


/****************************************************************
 * Misc fixed vars
 ****************************************************************/

char BiosCopyright[] VAR16FIXED(0xff00) =
    "(c) 2002 MandrakeSoft S.A. Written by Kevin Lawton & the Bochs team.";

// BIOS build date
char BiosDate[] VAR16FIXED(0xfff5) = "06/23/99";

u8 BiosModelId VAR16FIXED(0xfffe) = CONFIG_MODEL_ID;

u8 BiosChecksum VAR16FIXED(0xffff);

// XXX - Initial Interrupt Vector Offsets Loaded by POST
u8 InitVectors[13] VAR16FIXED(0xfef3);

// XXX - INT 1D - SYSTEM DATA - VIDEO PARAMETER TABLES
u8 VideoParams[88] VAR16FIXED(0xf0a4);
