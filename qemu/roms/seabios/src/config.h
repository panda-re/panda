#ifndef __CONFIG_H
#define __CONFIG_H

#include "autoconf.h"

// Configuration definitions.

//#define CONFIG_APPNAME  "QEMU"
//#define CONFIG_CPUNAME8 "QEMUCPU "
//#define CONFIG_APPNAME6 "QEMU  "
//#define CONFIG_APPNAME4 "QEMU"
#define CONFIG_APPNAME  "Bochs"
#define CONFIG_CPUNAME8 "BOCHSCPU"
#define CONFIG_APPNAME6 "BOCHS "
#define CONFIG_APPNAME4 "BXPC"

// Maximum number of map entries in the e820 map
#define CONFIG_MAX_E820 32
// Space to reserve in f-segment for dynamic allocations
#define CONFIG_MAX_BIOSTABLE 2048
// Space to reserve in high-memory for tables
#define CONFIG_MAX_HIGHTABLE (64*1024)
// Largest supported externaly facing drive id
#define CONFIG_MAX_EXTDRIVE 16

#define CONFIG_MODEL_ID      0xFC
#define CONFIG_SUBMODEL_ID   0x00
#define CONFIG_BIOS_REVISION 0x01

// Various memory addresses used by the code.
#define BUILD_STACK_ADDR          0x7000
#define BUILD_S3RESUME_STACK_ADDR 0x1000
#define BUILD_AP_BOOT_ADDR        0x10000
#define BUILD_EBDA_MINIMUM        0x90000
#define BUILD_LOWRAM_END          0xa0000
#define BUILD_ROM_START           0xc0000
#define BUILD_BIOS_ADDR           0xf0000
#define BUILD_BIOS_SIZE           0x10000
// 32KB for shadow ram copying (works around emulator deficiencies)
#define BUILD_BIOS_TMP_ADDR       0x30000
#define BUILD_MAX_HIGHMEM         0xe0000000

#define BUILD_PCIMEM_START        0xe0000000
#define BUILD_PCIMEM_SIZE         (BUILD_PCIMEM_END - BUILD_PCIMEM_START)
#define BUILD_PCIMEM_END          0xfec00000    /* IOAPIC is mapped at */

#define BUILD_APIC_ADDR           0xfee00000
#define BUILD_IOAPIC_ADDR         0xfec00000

#define BUILD_SMM_INIT_ADDR       0x38000
#define BUILD_SMM_ADDR            0xa8000
#define BUILD_SMM_SIZE            0x8000

#define BUILD_MAX_SMBIOS_FSEG     600

// Important real-mode segments
#define SEG_IVT      0x0000
#define SEG_BDA      0x0040
#define SEG_BIOS     0xf000

// Segment definitions in protected mode (see rombios32_gdt in misc.c)
#define SEG32_MODE32_CS    (1 << 3)
#define SEG32_MODE32_DS    (2 << 3)
#define SEG32_MODE16_CS    (3 << 3)
#define SEG32_MODE16_DS    (4 << 3)
#define SEG32_MODE16BIG_CS (5 << 3)
#define SEG32_MODE16BIG_DS (6 << 3)

// Debugging levels.  If non-zero and CONFIG_DEBUG_LEVEL is greater
// than the specified value, then the corresponding irq handler will
// report every enter event.
#define DEBUG_ISR_02 1
#define DEBUG_HDL_05 1
#define DEBUG_ISR_08 20
#define DEBUG_ISR_09 9
#define DEBUG_ISR_0e 9
#define DEBUG_HDL_10 20
#define DEBUG_HDL_11 2
#define DEBUG_HDL_12 2
#define DEBUG_HDL_13 10
#define DEBUG_HDL_14 2
#define DEBUG_HDL_15 9
#define DEBUG_HDL_16 9
#define DEBUG_HDL_17 2
#define DEBUG_HDL_18 1
#define DEBUG_HDL_19 1
#define DEBUG_HDL_1a 9
#define DEBUG_HDL_40 1
#define DEBUG_ISR_70 9
#define DEBUG_ISR_74 9
#define DEBUG_ISR_75 1
#define DEBUG_ISR_76 10
#define DEBUG_ISR_hwpic1 5
#define DEBUG_ISR_hwpic2 5
#define DEBUG_HDL_pnp 1
#define DEBUG_HDL_pmm 1
#define DEBUG_HDL_pcibios32 9
#define DEBUG_HDL_apm 9

#define DEBUG_unimplemented 2
#define DEBUG_invalid 3
#define DEBUG_thread 2

#endif // config.h
