// CPU count detection
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2006 Fabrice Bellard
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "config.h" // CONFIG_*
#include "cmos.h" // CMOS_BIOS_SMP_COUNT
#include "paravirt.h"

#define APIC_ICR_LOW ((u8*)BUILD_APIC_ADDR + 0x300)
#define APIC_SVR     ((u8*)BUILD_APIC_ADDR + 0x0F0)
#define APIC_LINT0   ((u8*)BUILD_APIC_ADDR + 0x350)
#define APIC_LINT1   ((u8*)BUILD_APIC_ADDR + 0x360)

#define APIC_ENABLED 0x0100

struct { u32 ecx, eax, edx; } smp_mtrr[32] VAR16VISIBLE;
u32 smp_mtrr_count VAR16VISIBLE;

void
wrmsr_smp(u32 index, u64 val)
{
    wrmsr(index, val);
    if (smp_mtrr_count >= ARRAY_SIZE(smp_mtrr)) {
        warn_noalloc();
        return;
    }
    smp_mtrr[smp_mtrr_count].ecx = index;
    smp_mtrr[smp_mtrr_count].eax = val;
    smp_mtrr[smp_mtrr_count].edx = val >> 32;
    smp_mtrr_count++;
}

u32 CountCPUs VAR16VISIBLE;
u32 MaxCountCPUs VAR16VISIBLE;
extern void smp_ap_boot_code(void);
ASM16(
    "  .global smp_ap_boot_code\n"
    "smp_ap_boot_code:\n"

    // Setup data segment
    "  movw $" __stringify(SEG_BIOS) ", %ax\n"
    "  movw %ax, %ds\n"

    // MTRR setup
    "  movl $smp_mtrr, %esi\n"
    "  movl smp_mtrr_count, %ebx\n"
    "1:testl %ebx, %ebx\n"
    "  jz 2f\n"
    "  movl 0(%esi), %ecx\n"
    "  movl 4(%esi), %eax\n"
    "  movl 8(%esi), %edx\n"
    "  wrmsr\n"
    "  addl $12, %esi\n"
    "  decl %ebx\n"
    "  jmp 1b\n"
    "2:\n"

    // Increment the cpu counter
    "  lock incl CountCPUs\n"

    // Halt the processor.
    "1:hlt\n"
    "  jmp 1b\n"
    );

// find and initialize the CPUs by launching a SIPI to them
void
smp_probe(void)
{
    ASSERT32FLAT();
    u32 eax, ebx, ecx, cpuid_features;
    cpuid(1, &eax, &ebx, &ecx, &cpuid_features);
    if (eax < 1 || !(cpuid_features & CPUID_APIC)) {
        // No apic - only the main cpu is present.
        dprintf(1, "No apic - only the main cpu is present.\n");
        CountCPUs= 1;
        MaxCountCPUs = 1;
        return;
    }

    // Init the counter.
    writel(&CountCPUs, 1);

    // Setup jump trampoline to counter code.
    u64 old = *(u64*)BUILD_AP_BOOT_ADDR;
    // ljmpw $SEG_BIOS, $(smp_ap_boot_code - BUILD_BIOS_ADDR)
    u64 new = (0xea | ((u64)SEG_BIOS<<24)
               | (((u32)smp_ap_boot_code - BUILD_BIOS_ADDR) << 8));
    *(u64*)BUILD_AP_BOOT_ADDR = new;

    // enable local APIC
    u32 val = readl(APIC_SVR);
    writel(APIC_SVR, val | APIC_ENABLED);

    if (! CONFIG_COREBOOT) {
        /* Set LINT0 as Ext_INT, level triggered */
        writel(APIC_LINT0, 0x8700);

        /* Set LINT1 as NMI, level triggered */
        writel(APIC_LINT1, 0x8400);
    }

    // broadcast SIPI
    barrier();
    writel(APIC_ICR_LOW, 0x000C4500);
    u32 sipi_vector = BUILD_AP_BOOT_ADDR >> 12;
    writel(APIC_ICR_LOW, 0x000C4600 | sipi_vector);

    // Wait for other CPUs to process the SIPI.
    if (CONFIG_COREBOOT) {
        msleep(10);
    } else {
        u8 cmos_smp_count = inb_cmos(CMOS_BIOS_SMP_COUNT);
        while (cmos_smp_count + 1 != readl(&CountCPUs))
            yield();
    }

    // Restore memory.
    *(u64*)BUILD_AP_BOOT_ADDR = old;

    MaxCountCPUs = qemu_cfg_get_max_cpus();
    if (!MaxCountCPUs || MaxCountCPUs < CountCPUs)
        MaxCountCPUs = CountCPUs;

    dprintf(1, "Found %d cpu(s) max supported %d cpu(s)\n", readl(&CountCPUs),
        MaxCountCPUs);
}
