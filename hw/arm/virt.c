/*
 * ARM mach-virt emulation
 *
 * Copyright (c) 2013 Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Emulate a virtual board which works by passing Linux all the information
 * it needs about what devices are present via the device tree.
 * There are some restrictions about what we can do here:
 *  + we can only present devices whose Linux drivers will work based
 *    purely on the device tree with no platform data at all
 *  + we want to present a very stripped-down minimalist platform,
 *    both because this reduces the security attack surface from the guest
 *    and also because it reduces our exposure to being broken when
 *    the kernel updates its device tree bindings and requires further
 *    information in a device binding that we aren't providing.
 * This is essentially the same approach kvmtool uses.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/arm/arm.h"
#include "hw/arm/primecell.h"
#include "hw/arm/virt.h"
#include "hw/devices.h"
#include "net/net.h"
#include "sysemu/block-backend.h"
#include "sysemu/device_tree.h"
#include "sysemu/numa.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "hw/compat.h"
#include "hw/loader.h"
#include "exec/address-spaces.h"
#include "qemu/bitops.h"
#include "qemu/error-report.h"
#include "hw/pci-host/gpex.h"
#include "hw/arm/sysbus-fdt.h"
#include "hw/platform-bus.h"
#include "hw/arm/fdt.h"
#include "hw/intc/arm_gic.h"
#include "hw/intc/arm_gicv3_common.h"
#include "kvm_arm.h"
#include "hw/smbios/smbios.h"
#include "qapi/visitor.h"
#include "standard-headers/linux/input.h"

#define DEFINE_VIRT_MACHINE_LATEST(major, minor, latest) \
    static void virt_##major##_##minor##_class_init(ObjectClass *oc, \
                                                    void *data) \
    { \
        MachineClass *mc = MACHINE_CLASS(oc); \
        virt_machine_##major##_##minor##_options(mc); \
        mc->desc = "QEMU " # major "." # minor " ARM Virtual Machine"; \
        if (latest) { \
            mc->alias = "virt"; \
        } \
    } \
    static const TypeInfo machvirt_##major##_##minor##_info = { \
        .name = MACHINE_TYPE_NAME("virt-" # major "." # minor), \
        .parent = TYPE_VIRT_MACHINE, \
        .instance_init = virt_##major##_##minor##_instance_init, \
        .class_init = virt_##major##_##minor##_class_init, \
    }; \
    static void machvirt_machine_##major##_##minor##_init(void) \
    { \
        type_register_static(&machvirt_##major##_##minor##_info); \
    } \
    type_init(machvirt_machine_##major##_##minor##_init);

#define DEFINE_VIRT_MACHINE_AS_LATEST(major, minor) \
    DEFINE_VIRT_MACHINE_LATEST(major, minor, true)
#define DEFINE_VIRT_MACHINE(major, minor) \
    DEFINE_VIRT_MACHINE_LATEST(major, minor, false)


/* Number of external interrupt lines to configure the GIC with */
#define NUM_IRQS 256

#define PLATFORM_BUS_NUM_IRQS 64

static ARMPlatformBusSystemParams platform_bus_params;

/* RAM limit in GB. Since VIRT_MEM starts at the 1GB mark, this means
 * RAM can go up to the 256GB mark, leaving 256GB of the physical
 * address space unallocated and free for future use between 256G and 512G.
 * If we need to provide more RAM to VMs in the future then we need to:
 *  * allocate a second bank of RAM starting at 2TB and working up
 *  * fix the DT and ACPI table generation code in QEMU to correctly
 *    report two split lumps of RAM to the guest
 *  * fix KVM in the host kernel to allow guests with >40 bit address spaces
 * (We don't want to fill all the way up to 512GB with RAM because
 * we might want it for non-RAM purposes later. Conversely it seems
 * reasonable to assume that anybody configuring a VM with a quarter
 * of a terabyte of RAM will be doing it on a host with more than a
 * terabyte of physical address space.)
 */
#define RAMLIMIT_GB 255
#define RAMLIMIT_BYTES (RAMLIMIT_GB * 1024ULL * 1024 * 1024)

/* Addresses and sizes of our components.
 * 0..128MB is space for a flash device so we can run bootrom code such as UEFI.
 * 128MB..256MB is used for miscellaneous device I/O.
 * 256MB..1GB is reserved for possible future PCI support (ie where the
 * PCI memory window will go if we add a PCI host controller).
 * 1GB and up is RAM (which may happily spill over into the
 * high memory region beyond 4GB).
 * This represents a compromise between how much RAM can be given to
 * a 32 bit VM and leaving space for expansion and in particular for PCI.
 * Note that devices should generally be placed at multiples of 0x10000,
 * to accommodate guests using 64K pages.
 */
static const MemMapEntry a15memmap[] = {
    /* Space up to 0x8000000 is reserved for a boot ROM */
    [VIRT_FLASH] =              {          0, 0x08000000 },
    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
    /* GIC distributor and CPU interfaces sit inside the CPU peripheral space */
    [VIRT_GIC_DIST] =           { 0x08000000, 0x00010000 },
    [VIRT_GIC_CPU] =            { 0x08010000, 0x00010000 },
    [VIRT_GIC_V2M] =            { 0x08020000, 0x00001000 },
    /* The space in between here is reserved for GICv3 CPU/vCPU/HYP */
    [VIRT_GIC_ITS] =            { 0x08080000, 0x00020000 },
    /* This redistributor space allows up to 2*64kB*123 CPUs */
    [VIRT_GIC_REDIST] =         { 0x080A0000, 0x00F60000 },
    [VIRT_UART0] =              { 0x09000000, 0x00001000 },
    [VIRT_RTC] =                { 0x09010000, 0x00001000 },
    [VIRT_FW_CFG] =             { 0x09020000, 0x00000018 },
    [VIRT_GPIO] =               { 0x09030000, 0x00001000 },
    [VIRT_SECURE_UART] =        { 0x09040000, 0x00001000 },
    [VIRT_UART1] =              { 0x09080000, 0x00001000 },
    [VIRT_UART2] =              { 0x09090000, 0x00001000 },
    [VIRT_UART3] =              { 0x090a0000, 0x00001000 },
    [VIRT_MMIO] =               { 0x0a000000, 0x00000200 },
    /* ...repeating for a total of NUM_VIRTIO_TRANSPORTS, each of that size */
    [VIRT_PLATFORM_BUS] =       { 0x0c000000, 0x02000000 },
    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
    [VIRT_PCIE_MMIO] =          { 0x10000000, 0x2eff0000 },
    [VIRT_PCIE_PIO] =           { 0x3eff0000, 0x00010000 },
    [VIRT_PCIE_ECAM] =          { 0x3f000000, 0x01000000 },
    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
    /* Second PCIe window, 512GB wide at the 512GB boundary */
    [VIRT_PCIE_MMIO_HIGH] =   { 0x8000000000ULL, 0x8000000000ULL },
};

static const int a15irqmap[] = {
    [VIRT_UART0] = 1,
    [VIRT_RTC] = 2,
    [VIRT_PCIE] = 3, /* ... to 6 */
    [VIRT_GPIO] = 7,
    [VIRT_SECURE_UART] = 8,
    [VIRT_UART1] = 9,
    [VIRT_UART2] = 10,
    [VIRT_UART3] = 11,
    [VIRT_MMIO] = 16, /* ...to 16 + NUM_VIRTIO_TRANSPORTS - 1 */
    [VIRT_GIC_V2M] = 48, /* ...to 48 + NUM_GICV2M_SPIS - 1 */
    [VIRT_PLATFORM_BUS] = 112, /* ...to 112 + PLATFORM_BUS_NUM_IRQS -1 */
};

static const char *valid_cpus[] = {
    "cortex-a15",
    "cortex-a53",
    "cortex-a57",
    "host",
};

static bool cpuname_valid(const char *cpu)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(valid_cpus); i++) {
        if (strcmp(cpu, valid_cpus[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void create_fdt(VirtMachineState *vms)
{
    void *fdt = create_device_tree(&vms->fdt_size);

    if (!fdt) {
        error_report("create_device_tree() failed");
        exit(1);
    }

    vms->fdt = fdt;

    /* Header */
    qemu_fdt_setprop_string(fdt, "/", "compatible", "linux,dummy-virt");
    qemu_fdt_setprop_cell(fdt, "/", "#address-cells", 0x2);
    qemu_fdt_setprop_cell(fdt, "/", "#size-cells", 0x2);

    /*
     * /chosen and /memory nodes must exist for load_dtb
     * to fill in necessary properties later
     */
    qemu_fdt_add_subnode(fdt, "/chosen");
    qemu_fdt_add_subnode(fdt, "/memory");
    qemu_fdt_setprop_string(fdt, "/memory", "device_type", "memory");

    /* Clock node, for the benefit of the UART. The kernel device tree
     * binding documentation claims the PL011 node clock properties are
     * optional but in practice if you omit them the kernel refuses to
     * probe for the device.
     */
    vms->clock_phandle = qemu_fdt_alloc_phandle(fdt);
    qemu_fdt_add_subnode(fdt, "/apb-pclk");
    qemu_fdt_setprop_string(fdt, "/apb-pclk", "compatible", "fixed-clock");
    qemu_fdt_setprop_cell(fdt, "/apb-pclk", "#clock-cells", 0x0);
    qemu_fdt_setprop_cell(fdt, "/apb-pclk", "clock-frequency", 24000000);
    qemu_fdt_setprop_string(fdt, "/apb-pclk", "clock-output-names",
                                "clk24mhz");
    qemu_fdt_setprop_cell(fdt, "/apb-pclk", "phandle", vms->clock_phandle);

}

static void fdt_add_psci_node(const VirtMachineState *vms)
{
    uint32_t cpu_suspend_fn;
    uint32_t cpu_off_fn;
    uint32_t cpu_on_fn;
    uint32_t migrate_fn;
    void *fdt = vms->fdt;
    ARMCPU *armcpu = ARM_CPU(qemu_get_cpu(0));
    const char *psci_method;

    switch (vms->psci_conduit) {
    case QEMU_PSCI_CONDUIT_DISABLED:
        return;
    case QEMU_PSCI_CONDUIT_HVC:
        psci_method = "hvc";
        break;
    case QEMU_PSCI_CONDUIT_SMC:
        psci_method = "smc";
        break;
    default:
        g_assert_not_reached();
    }

    qemu_fdt_add_subnode(fdt, "/psci");
    if (armcpu->psci_version == 2) {
        const char comp[] = "arm,psci-0.2\0arm,psci";
        qemu_fdt_setprop(fdt, "/psci", "compatible", comp, sizeof(comp));

        cpu_off_fn = QEMU_PSCI_0_2_FN_CPU_OFF;
        if (arm_feature(&armcpu->env, ARM_FEATURE_AARCH64)) {
            cpu_suspend_fn = QEMU_PSCI_0_2_FN64_CPU_SUSPEND;
            cpu_on_fn = QEMU_PSCI_0_2_FN64_CPU_ON;
            migrate_fn = QEMU_PSCI_0_2_FN64_MIGRATE;
        } else {
            cpu_suspend_fn = QEMU_PSCI_0_2_FN_CPU_SUSPEND;
            cpu_on_fn = QEMU_PSCI_0_2_FN_CPU_ON;
            migrate_fn = QEMU_PSCI_0_2_FN_MIGRATE;
        }
    } else {
        qemu_fdt_setprop_string(fdt, "/psci", "compatible", "arm,psci");

        cpu_suspend_fn = QEMU_PSCI_0_1_FN_CPU_SUSPEND;
        cpu_off_fn = QEMU_PSCI_0_1_FN_CPU_OFF;
        cpu_on_fn = QEMU_PSCI_0_1_FN_CPU_ON;
        migrate_fn = QEMU_PSCI_0_1_FN_MIGRATE;
    }

    /* We adopt the PSCI spec's nomenclature, and use 'conduit' to refer
     * to the instruction that should be used to invoke PSCI functions.
     * However, the device tree binding uses 'method' instead, so that is
     * what we should use here.
     */
    qemu_fdt_setprop_string(fdt, "/psci", "method", psci_method);

    qemu_fdt_setprop_cell(fdt, "/psci", "cpu_suspend", cpu_suspend_fn);
    qemu_fdt_setprop_cell(fdt, "/psci", "cpu_off", cpu_off_fn);
    qemu_fdt_setprop_cell(fdt, "/psci", "cpu_on", cpu_on_fn);
    qemu_fdt_setprop_cell(fdt, "/psci", "migrate", migrate_fn);
}

static void fdt_add_timer_nodes(const VirtMachineState *vms)
{
    /* On real hardware these interrupts are level-triggered.
     * On KVM they were edge-triggered before host kernel version 4.4,
     * and level-triggered afterwards.
     * On emulated QEMU they are level-triggered.
     *
     * Getting the DTB info about them wrong is awkward for some
     * guest kernels:
     *  pre-4.8 ignore the DT and leave the interrupt configured
     *   with whatever the GIC reset value (or the bootloader) left it at
     *  4.8 before rc6 honour the incorrect data by programming it back
     *   into the GIC, causing problems
     *  4.8rc6 and later ignore the DT and always write "level triggered"
     *   into the GIC
     *
     * For backwards-compatibility, virt-2.8 and earlier will continue
     * to say these are edge-triggered, but later machines will report
     * the correct information.
     */
    ARMCPU *armcpu;
    VirtMachineClass *vmc = VIRT_MACHINE_GET_CLASS(vms);
    uint32_t irqflags = GIC_FDT_IRQ_FLAGS_LEVEL_HI;

    if (vmc->claim_edge_triggered_timers) {
        irqflags = GIC_FDT_IRQ_FLAGS_EDGE_LO_HI;
    }

    if (vms->gic_version == 2) {
        irqflags = deposit32(irqflags, GIC_FDT_IRQ_PPI_CPU_START,
                             GIC_FDT_IRQ_PPI_CPU_WIDTH,
                             (1 << vms->smp_cpus) - 1);
    }

    qemu_fdt_add_subnode(vms->fdt, "/timer");

    armcpu = ARM_CPU(qemu_get_cpu(0));
    if (arm_feature(&armcpu->env, ARM_FEATURE_V8)) {
        const char compat[] = "arm,armv8-timer\0arm,armv7-timer";
        qemu_fdt_setprop(vms->fdt, "/timer", "compatible",
                         compat, sizeof(compat));
    } else {
        qemu_fdt_setprop_string(vms->fdt, "/timer", "compatible",
                                "arm,armv7-timer");
    }
    qemu_fdt_setprop(vms->fdt, "/timer", "always-on", NULL, 0);
    qemu_fdt_setprop_cells(vms->fdt, "/timer", "interrupts",
                       GIC_FDT_IRQ_TYPE_PPI, ARCH_TIMER_S_EL1_IRQ, irqflags,
                       GIC_FDT_IRQ_TYPE_PPI, ARCH_TIMER_NS_EL1_IRQ, irqflags,
                       GIC_FDT_IRQ_TYPE_PPI, ARCH_TIMER_VIRT_IRQ, irqflags,
                       GIC_FDT_IRQ_TYPE_PPI, ARCH_TIMER_NS_EL2_IRQ, irqflags);
}

static void fdt_add_cpu_nodes(const VirtMachineState *vms)
{
    int cpu;
    int addr_cells = 1;
    unsigned int i;

    /*
     * From Documentation/devicetree/bindings/arm/cpus.txt
     *  On ARM v8 64-bit systems value should be set to 2,
     *  that corresponds to the MPIDR_EL1 register size.
     *  If MPIDR_EL1[63:32] value is equal to 0 on all CPUs
     *  in the system, #address-cells can be set to 1, since
     *  MPIDR_EL1[63:32] bits are not used for CPUs
     *  identification.
     *
     *  Here we actually don't know whether our system is 32- or 64-bit one.
     *  The simplest way to go is to examine affinity IDs of all our CPUs. If
     *  at least one of them has Aff3 populated, we set #address-cells to 2.
     */
    for (cpu = 0; cpu < vms->smp_cpus; cpu++) {
        ARMCPU *armcpu = ARM_CPU(qemu_get_cpu(cpu));

        if (armcpu->mp_affinity & ARM_AFF3_MASK) {
            addr_cells = 2;
            break;
        }
    }

    qemu_fdt_add_subnode(vms->fdt, "/cpus");
    qemu_fdt_setprop_cell(vms->fdt, "/cpus", "#address-cells", addr_cells);
    qemu_fdt_setprop_cell(vms->fdt, "/cpus", "#size-cells", 0x0);

    for (cpu = vms->smp_cpus - 1; cpu >= 0; cpu--) {
        char *nodename = g_strdup_printf("/cpus/cpu@%d", cpu);
        ARMCPU *armcpu = ARM_CPU(qemu_get_cpu(cpu));

        qemu_fdt_add_subnode(vms->fdt, nodename);
        qemu_fdt_setprop_string(vms->fdt, nodename, "device_type", "cpu");
        qemu_fdt_setprop_string(vms->fdt, nodename, "compatible",
                                    armcpu->dtb_compatible);

        if (vms->psci_conduit != QEMU_PSCI_CONDUIT_DISABLED
            && vms->smp_cpus > 1) {
            qemu_fdt_setprop_string(vms->fdt, nodename,
                                        "enable-method", "psci");
        }

        if (addr_cells == 2) {
            qemu_fdt_setprop_u64(vms->fdt, nodename, "reg",
                                 armcpu->mp_affinity);
        } else {
            qemu_fdt_setprop_cell(vms->fdt, nodename, "reg",
                                  armcpu->mp_affinity);
        }

        i = numa_get_node_for_cpu(cpu);
        if (i < nb_numa_nodes) {
            qemu_fdt_setprop_cell(vms->fdt, nodename, "numa-node-id", i);
        }

        g_free(nodename);
    }
}

static void fdt_add_its_gic_node(VirtMachineState *vms)
{
    vms->msi_phandle = qemu_fdt_alloc_phandle(vms->fdt);
    qemu_fdt_add_subnode(vms->fdt, "/intc/its");
    qemu_fdt_setprop_string(vms->fdt, "/intc/its", "compatible",
                            "arm,gic-v3-its");
    qemu_fdt_setprop(vms->fdt, "/intc/its", "msi-controller", NULL, 0);
    qemu_fdt_setprop_sized_cells(vms->fdt, "/intc/its", "reg",
                                 2, vms->memmap[VIRT_GIC_ITS].base,
                                 2, vms->memmap[VIRT_GIC_ITS].size);
    qemu_fdt_setprop_cell(vms->fdt, "/intc/its", "phandle", vms->msi_phandle);
}

static void fdt_add_v2m_gic_node(VirtMachineState *vms)
{
    vms->msi_phandle = qemu_fdt_alloc_phandle(vms->fdt);
    qemu_fdt_add_subnode(vms->fdt, "/intc/v2m");
    qemu_fdt_setprop_string(vms->fdt, "/intc/v2m", "compatible",
                            "arm,gic-v2m-frame");
    qemu_fdt_setprop(vms->fdt, "/intc/v2m", "msi-controller", NULL, 0);
    qemu_fdt_setprop_sized_cells(vms->fdt, "/intc/v2m", "reg",
                                 2, vms->memmap[VIRT_GIC_V2M].base,
                                 2, vms->memmap[VIRT_GIC_V2M].size);
    qemu_fdt_setprop_cell(vms->fdt, "/intc/v2m", "phandle", vms->msi_phandle);
}

static void fdt_add_gic_node(VirtMachineState *vms)
{
    vms->gic_phandle = qemu_fdt_alloc_phandle(vms->fdt);
    qemu_fdt_setprop_cell(vms->fdt, "/", "interrupt-parent", vms->gic_phandle);

    qemu_fdt_add_subnode(vms->fdt, "/intc");
    qemu_fdt_setprop_cell(vms->fdt, "/intc", "#interrupt-cells", 3);
    qemu_fdt_setprop(vms->fdt, "/intc", "interrupt-controller", NULL, 0);
    qemu_fdt_setprop_cell(vms->fdt, "/intc", "#address-cells", 0x2);
    qemu_fdt_setprop_cell(vms->fdt, "/intc", "#size-cells", 0x2);
    qemu_fdt_setprop(vms->fdt, "/intc", "ranges", NULL, 0);
    if (vms->gic_version == 3) {
        qemu_fdt_setprop_string(vms->fdt, "/intc", "compatible",
                                "arm,gic-v3");
        qemu_fdt_setprop_sized_cells(vms->fdt, "/intc", "reg",
                                     2, vms->memmap[VIRT_GIC_DIST].base,
                                     2, vms->memmap[VIRT_GIC_DIST].size,
                                     2, vms->memmap[VIRT_GIC_REDIST].base,
                                     2, vms->memmap[VIRT_GIC_REDIST].size);
        if (vms->virt) {
            qemu_fdt_setprop_cells(vms->fdt, "/intc", "interrupts",
                                   GIC_FDT_IRQ_TYPE_PPI, ARCH_GICV3_MAINT_IRQ,
                                   GIC_FDT_IRQ_FLAGS_LEVEL_HI);
        }
    } else {
        /* 'cortex-a15-gic' means 'GIC v2' */
        qemu_fdt_setprop_string(vms->fdt, "/intc", "compatible",
                                "arm,cortex-a15-gic");
        qemu_fdt_setprop_sized_cells(vms->fdt, "/intc", "reg",
                                      2, vms->memmap[VIRT_GIC_DIST].base,
                                      2, vms->memmap[VIRT_GIC_DIST].size,
                                      2, vms->memmap[VIRT_GIC_CPU].base,
                                      2, vms->memmap[VIRT_GIC_CPU].size);
    }

    qemu_fdt_setprop_cell(vms->fdt, "/intc", "phandle", vms->gic_phandle);
}

static void fdt_add_pmu_nodes(const VirtMachineState *vms)
{
    CPUState *cpu;
    ARMCPU *armcpu;
    uint32_t irqflags = GIC_FDT_IRQ_FLAGS_LEVEL_HI;

    CPU_FOREACH(cpu) {
        armcpu = ARM_CPU(cpu);
        if (!arm_feature(&armcpu->env, ARM_FEATURE_PMU) ||
            (kvm_enabled() && !kvm_arm_pmu_create(cpu, PPI(VIRTUAL_PMU_IRQ)))) {
            return;
        }
    }

    if (vms->gic_version == 2) {
        irqflags = deposit32(irqflags, GIC_FDT_IRQ_PPI_CPU_START,
                             GIC_FDT_IRQ_PPI_CPU_WIDTH,
                             (1 << vms->smp_cpus) - 1);
    }

    armcpu = ARM_CPU(qemu_get_cpu(0));
    qemu_fdt_add_subnode(vms->fdt, "/pmu");
    if (arm_feature(&armcpu->env, ARM_FEATURE_V8)) {
        const char compat[] = "arm,armv8-pmuv3";
        qemu_fdt_setprop(vms->fdt, "/pmu", "compatible",
                         compat, sizeof(compat));
        qemu_fdt_setprop_cells(vms->fdt, "/pmu", "interrupts",
                               GIC_FDT_IRQ_TYPE_PPI, VIRTUAL_PMU_IRQ, irqflags);
    }
}

static void create_its(VirtMachineState *vms, DeviceState *gicdev)
{
    const char *itsclass = its_class_name();
    DeviceState *dev;

    if (!itsclass) {
        /* Do nothing if not supported */
        return;
    }

    dev = qdev_create(NULL, itsclass);

    object_property_set_link(OBJECT(dev), OBJECT(gicdev), "parent-gicv3",
                             &error_abort);
    qdev_init_nofail(dev);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, vms->memmap[VIRT_GIC_ITS].base);

    fdt_add_its_gic_node(vms);
}

static void create_v2m(VirtMachineState *vms, qemu_irq *pic)
{
    int i;
    int irq = vms->irqmap[VIRT_GIC_V2M];
    DeviceState *dev;

    dev = qdev_create(NULL, "arm-gicv2m");
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, vms->memmap[VIRT_GIC_V2M].base);
    qdev_prop_set_uint32(dev, "base-spi", irq);
    qdev_prop_set_uint32(dev, "num-spi", NUM_GICV2M_SPIS);
    qdev_init_nofail(dev);

    for (i = 0; i < NUM_GICV2M_SPIS; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), i, pic[irq + i]);
    }

    fdt_add_v2m_gic_node(vms);
}

static void create_gic(VirtMachineState *vms, qemu_irq *pic)
{
    /* We create a standalone GIC */
    DeviceState *gicdev;
    SysBusDevice *gicbusdev;
    const char *gictype;
    int type = vms->gic_version, i;

    gictype = (type == 3) ? gicv3_class_name() : gic_class_name();

    gicdev = qdev_create(NULL, gictype);
    qdev_prop_set_uint32(gicdev, "revision", type);
    qdev_prop_set_uint32(gicdev, "num-cpu", smp_cpus);
    /* Note that the num-irq property counts both internal and external
     * interrupts; there are always 32 of the former (mandated by GIC spec).
     */
    qdev_prop_set_uint32(gicdev, "num-irq", NUM_IRQS + 32);
    if (!kvm_irqchip_in_kernel()) {
        qdev_prop_set_bit(gicdev, "has-security-extensions", vms->secure);
    }
    qdev_init_nofail(gicdev);
    gicbusdev = SYS_BUS_DEVICE(gicdev);
    sysbus_mmio_map(gicbusdev, 0, vms->memmap[VIRT_GIC_DIST].base);
    if (type == 3) {
        sysbus_mmio_map(gicbusdev, 1, vms->memmap[VIRT_GIC_REDIST].base);
    } else {
        sysbus_mmio_map(gicbusdev, 1, vms->memmap[VIRT_GIC_CPU].base);
    }

    /* Wire the outputs from each CPU's generic timer and the GICv3
     * maintenance interrupt signal to the appropriate GIC PPI inputs,
     * and the GIC's IRQ/FIQ/VIRQ/VFIQ interrupt outputs to the CPU's inputs.
     */
    for (i = 0; i < smp_cpus; i++) {
        DeviceState *cpudev = DEVICE(qemu_get_cpu(i));
        int ppibase = NUM_IRQS + i * GIC_INTERNAL + GIC_NR_SGIS;
        int irq;
        /* Mapping from the output timer irq lines from the CPU to the
         * GIC PPI inputs we use for the virt board.
         */
        const int timer_irq[] = {
            [GTIMER_PHYS] = ARCH_TIMER_NS_EL1_IRQ,
            [GTIMER_VIRT] = ARCH_TIMER_VIRT_IRQ,
            [GTIMER_HYP]  = ARCH_TIMER_NS_EL2_IRQ,
            [GTIMER_SEC]  = ARCH_TIMER_S_EL1_IRQ,
        };

        for (irq = 0; irq < ARRAY_SIZE(timer_irq); irq++) {
            qdev_connect_gpio_out(cpudev, irq,
                                  qdev_get_gpio_in(gicdev,
                                                   ppibase + timer_irq[irq]));
        }

        qdev_connect_gpio_out_named(cpudev, "gicv3-maintenance-interrupt", 0,
                                    qdev_get_gpio_in(gicdev, ppibase
                                                     + ARCH_GICV3_MAINT_IRQ));

        sysbus_connect_irq(gicbusdev, i, qdev_get_gpio_in(cpudev, ARM_CPU_IRQ));
        sysbus_connect_irq(gicbusdev, i + smp_cpus,
                           qdev_get_gpio_in(cpudev, ARM_CPU_FIQ));
        sysbus_connect_irq(gicbusdev, i + 2 * smp_cpus,
                           qdev_get_gpio_in(cpudev, ARM_CPU_VIRQ));
        sysbus_connect_irq(gicbusdev, i + 3 * smp_cpus,
                           qdev_get_gpio_in(cpudev, ARM_CPU_VFIQ));
    }

    for (i = 0; i < NUM_IRQS; i++) {
        pic[i] = qdev_get_gpio_in(gicdev, i);
    }

    fdt_add_gic_node(vms);

    if (type == 3 && vms->its) {
        create_its(vms, gicdev);
    } else if (type == 2) {
        create_v2m(vms, pic);
    }
}

static void create_uart(const VirtMachineState *vms, qemu_irq *pic, int uart,
                        MemoryRegion *mem, Chardev *chr)
{
    char *nodename;
    hwaddr base = vms->memmap[uart].base;
    hwaddr size = vms->memmap[uart].size;
    int irq = vms->irqmap[uart];

   if(chr == NULL)
       return;

    const char compat[] = "arm,pl011\0arm,primecell";
    const char clocknames[] = "uartclk\0apb_pclk";

    DeviceState *dev = qdev_create(NULL, "pl011");
    SysBusDevice *s = SYS_BUS_DEVICE(dev);

    qdev_prop_set_chr(dev, "chardev", chr);
    qdev_init_nofail(dev);
    memory_region_add_subregion(mem, base,
                                sysbus_mmio_get_region(s, 0));
    sysbus_connect_irq(s, 0, pic[irq]);

    nodename = g_strdup_printf("/pl011@%" PRIx64, base);
    qemu_fdt_add_subnode(vms->fdt, nodename);
    /* Note that we can't use setprop_string because of the embedded NUL */
    qemu_fdt_setprop(vms->fdt, nodename, "compatible",
                         compat, sizeof(compat));
    qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                     2, base, 2, size);
    qemu_fdt_setprop_cells(vms->fdt, nodename, "interrupts",
                               GIC_FDT_IRQ_TYPE_SPI, irq,
                               GIC_FDT_IRQ_FLAGS_LEVEL_HI);
    qemu_fdt_setprop_cells(vms->fdt, nodename, "clocks",
                               vms->clock_phandle, vms->clock_phandle);
    qemu_fdt_setprop(vms->fdt, nodename, "clock-names",
                         clocknames, sizeof(clocknames));

    if (uart == VIRT_UART0) {
        qemu_fdt_setprop_string(vms->fdt, "/chosen", "stdout-path", nodename);
    } else if ((uart != VIRT_UART1) && (uart != VIRT_UART2) && (uart != VIRT_UART3))  {
        /* Mark as not usable by the normal world */
        qemu_fdt_setprop_string(vms->fdt, nodename, "status", "disabled");
        qemu_fdt_setprop_string(vms->fdt, nodename, "secure-status", "okay");
    }

    g_free(nodename);
}

static void create_rtc(const VirtMachineState *vms, qemu_irq *pic)
{
    char *nodename;
    hwaddr base = vms->memmap[VIRT_RTC].base;
    hwaddr size = vms->memmap[VIRT_RTC].size;
    int irq = vms->irqmap[VIRT_RTC];
    const char compat[] = "arm,pl031\0arm,primecell";

    sysbus_create_simple("pl031", base, pic[irq]);

    nodename = g_strdup_printf("/pl031@%" PRIx64, base);
    qemu_fdt_add_subnode(vms->fdt, nodename);
    qemu_fdt_setprop(vms->fdt, nodename, "compatible", compat, sizeof(compat));
    qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                 2, base, 2, size);
    qemu_fdt_setprop_cells(vms->fdt, nodename, "interrupts",
                           GIC_FDT_IRQ_TYPE_SPI, irq,
                           GIC_FDT_IRQ_FLAGS_LEVEL_HI);
    qemu_fdt_setprop_cell(vms->fdt, nodename, "clocks", vms->clock_phandle);
    qemu_fdt_setprop_string(vms->fdt, nodename, "clock-names", "apb_pclk");
    g_free(nodename);
}

static DeviceState *gpio_key_dev;
static void virt_powerdown_req(Notifier *n, void *opaque)
{
    /* use gpio Pin 3 for power button event */
    qemu_set_irq(qdev_get_gpio_in(gpio_key_dev, 0), 1);
}

static Notifier virt_system_powerdown_notifier = {
    .notify = virt_powerdown_req
};

static void create_gpio(const VirtMachineState *vms, qemu_irq *pic)
{
    char *nodename;
    DeviceState *pl061_dev;
    hwaddr base = vms->memmap[VIRT_GPIO].base;
    hwaddr size = vms->memmap[VIRT_GPIO].size;
    int irq = vms->irqmap[VIRT_GPIO];
    const char compat[] = "arm,pl061\0arm,primecell";

    pl061_dev = sysbus_create_simple("pl061", base, pic[irq]);

    uint32_t phandle = qemu_fdt_alloc_phandle(vms->fdt);
    nodename = g_strdup_printf("/pl061@%" PRIx64, base);
    qemu_fdt_add_subnode(vms->fdt, nodename);
    qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                 2, base, 2, size);
    qemu_fdt_setprop(vms->fdt, nodename, "compatible", compat, sizeof(compat));
    qemu_fdt_setprop_cell(vms->fdt, nodename, "#gpio-cells", 2);
    qemu_fdt_setprop(vms->fdt, nodename, "gpio-controller", NULL, 0);
    qemu_fdt_setprop_cells(vms->fdt, nodename, "interrupts",
                           GIC_FDT_IRQ_TYPE_SPI, irq,
                           GIC_FDT_IRQ_FLAGS_LEVEL_HI);
    qemu_fdt_setprop_cell(vms->fdt, nodename, "clocks", vms->clock_phandle);
    qemu_fdt_setprop_string(vms->fdt, nodename, "clock-names", "apb_pclk");
    qemu_fdt_setprop_cell(vms->fdt, nodename, "phandle", phandle);

    gpio_key_dev = sysbus_create_simple("gpio-key", -1,
                                        qdev_get_gpio_in(pl061_dev, 3));
    qemu_fdt_add_subnode(vms->fdt, "/gpio-keys");
    qemu_fdt_setprop_string(vms->fdt, "/gpio-keys", "compatible", "gpio-keys");
    qemu_fdt_setprop_cell(vms->fdt, "/gpio-keys", "#size-cells", 0);
    qemu_fdt_setprop_cell(vms->fdt, "/gpio-keys", "#address-cells", 1);

    qemu_fdt_add_subnode(vms->fdt, "/gpio-keys/poweroff");
    qemu_fdt_setprop_string(vms->fdt, "/gpio-keys/poweroff",
                            "label", "GPIO Key Poweroff");
    qemu_fdt_setprop_cell(vms->fdt, "/gpio-keys/poweroff", "linux,code",
                          KEY_POWER);
    qemu_fdt_setprop_cells(vms->fdt, "/gpio-keys/poweroff",
                           "gpios", phandle, 3, 0);

    /* connect powerdown request */
    qemu_register_powerdown_notifier(&virt_system_powerdown_notifier);

    g_free(nodename);
}

static void create_virtio_devices(const VirtMachineState *vms, qemu_irq *pic)
{
    int i;
    hwaddr size = vms->memmap[VIRT_MMIO].size;

    /* We create the transports in forwards order. Since qbus_realize()
     * prepends (not appends) new child buses, the incrementing loop below will
     * create a list of virtio-mmio buses with decreasing base addresses.
     *
     * When a -device option is processed from the command line,
     * qbus_find_recursive() picks the next free virtio-mmio bus in forwards
     * order. The upshot is that -device options in increasing command line
     * order are mapped to virtio-mmio buses with decreasing base addresses.
     *
     * When this code was originally written, that arrangement ensured that the
     * guest Linux kernel would give the lowest "name" (/dev/vda, eth0, etc) to
     * the first -device on the command line. (The end-to-end order is a
     * function of this loop, qbus_realize(), qbus_find_recursive(), and the
     * guest kernel's name-to-address assignment strategy.)
     *
     * Meanwhile, the kernel's traversal seems to have been reversed; see eg.
     * the message, if not necessarily the code, of commit 70161ff336.
     * Therefore the loop now establishes the inverse of the original intent.
     *
     * Unfortunately, we can't counteract the kernel change by reversing the
     * loop; it would break existing command lines.
     *
     * In any case, the kernel makes no guarantee about the stability of
     * enumeration order of virtio devices (as demonstrated by it changing
     * between kernel versions). For reliable and stable identification
     * of disks users must use UUIDs or similar mechanisms.
     */
    for (i = 0; i < NUM_VIRTIO_TRANSPORTS; i++) {
        int irq = vms->irqmap[VIRT_MMIO] + i;
        hwaddr base = vms->memmap[VIRT_MMIO].base + i * size;

        sysbus_create_simple("virtio-mmio", base, pic[irq]);
    }

    /* We add dtb nodes in reverse order so that they appear in the finished
     * device tree lowest address first.
     *
     * Note that this mapping is independent of the loop above. The previous
     * loop influences virtio device to virtio transport assignment, whereas
     * this loop controls how virtio transports are laid out in the dtb.
     */
    for (i = NUM_VIRTIO_TRANSPORTS - 1; i >= 0; i--) {
        char *nodename;
        int irq = vms->irqmap[VIRT_MMIO] + i;
        hwaddr base = vms->memmap[VIRT_MMIO].base + i * size;

        nodename = g_strdup_printf("/virtio_mmio@%" PRIx64, base);
        qemu_fdt_add_subnode(vms->fdt, nodename);
        qemu_fdt_setprop_string(vms->fdt, nodename,
                                "compatible", "virtio,mmio");
        qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                     2, base, 2, size);
        qemu_fdt_setprop_cells(vms->fdt, nodename, "interrupts",
                               GIC_FDT_IRQ_TYPE_SPI, irq,
                               GIC_FDT_IRQ_FLAGS_EDGE_LO_HI);
        qemu_fdt_setprop(vms->fdt, nodename, "dma-coherent", NULL, 0);
        g_free(nodename);
    }
}

static void create_one_flash(const char *name, hwaddr flashbase,
                             hwaddr flashsize, const char *file,
                             MemoryRegion *sysmem)
{
    /* Create and map a single flash device. We use the same
     * parameters as the flash devices on the Versatile Express board.
     */
    DriveInfo *dinfo = drive_get_next(IF_PFLASH);
    DeviceState *dev = qdev_create(NULL, "cfi.pflash01");
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    const uint64_t sectorlength = 256 * 1024;

    if (dinfo) {
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo),
                            &error_abort);
    }

    qdev_prop_set_uint32(dev, "num-blocks", flashsize / sectorlength);
    qdev_prop_set_uint64(dev, "sector-length", sectorlength);
    qdev_prop_set_uint8(dev, "width", 4);
    qdev_prop_set_uint8(dev, "device-width", 2);
    qdev_prop_set_bit(dev, "big-endian", false);
    qdev_prop_set_uint16(dev, "id0", 0x89);
    qdev_prop_set_uint16(dev, "id1", 0x18);
    qdev_prop_set_uint16(dev, "id2", 0x00);
    qdev_prop_set_uint16(dev, "id3", 0x00);
    qdev_prop_set_string(dev, "name", name);
    qdev_init_nofail(dev);

    memory_region_add_subregion(sysmem, flashbase,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0));

    if (file) {
        char *fn;
        int image_size;

        if (drive_get(IF_PFLASH, 0, 0)) {
            error_report("The contents of the first flash device may be "
                         "specified with -bios or with -drive if=pflash... "
                         "but you cannot use both options at once");
            exit(1);
        }
        fn = qemu_find_file(QEMU_FILE_TYPE_BIOS, file);
        if (!fn) {
            error_report("Could not find ROM image '%s'", file);
            exit(1);
        }
        image_size = load_image_mr(fn, sysbus_mmio_get_region(sbd, 0));
        g_free(fn);
        if (image_size < 0) {
            error_report("Could not load ROM image '%s'", file);
            exit(1);
        }
    }
}

static void create_flash(const VirtMachineState *vms,
                         MemoryRegion *sysmem,
                         MemoryRegion *secure_sysmem)
{
    /* Create two flash devices to fill the VIRT_FLASH space in the memmap.
     * Any file passed via -bios goes in the first of these.
     * sysmem is the system memory space. secure_sysmem is the secure view
     * of the system, and the first flash device should be made visible only
     * there. The second flash device is visible to both secure and nonsecure.
     * If sysmem == secure_sysmem this means there is no separate Secure
     * address space and both flash devices are generally visible.
     */
    hwaddr flashsize = vms->memmap[VIRT_FLASH].size / 2;
    hwaddr flashbase = vms->memmap[VIRT_FLASH].base;
    char *nodename;

    create_one_flash("virt.flash0", flashbase, flashsize,
                     bios_name, secure_sysmem);
    create_one_flash("virt.flash1", flashbase + flashsize, flashsize,
                     NULL, sysmem);

    if (sysmem == secure_sysmem) {
        /* Report both flash devices as a single node in the DT */
        nodename = g_strdup_printf("/flash@%" PRIx64, flashbase);
        qemu_fdt_add_subnode(vms->fdt, nodename);
        qemu_fdt_setprop_string(vms->fdt, nodename, "compatible", "cfi-flash");
        qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                     2, flashbase, 2, flashsize,
                                     2, flashbase + flashsize, 2, flashsize);
        qemu_fdt_setprop_cell(vms->fdt, nodename, "bank-width", 4);
        g_free(nodename);
    } else {
        /* Report the devices as separate nodes so we can mark one as
         * only visible to the secure world.
         */
        nodename = g_strdup_printf("/secflash@%" PRIx64, flashbase);
        qemu_fdt_add_subnode(vms->fdt, nodename);
        qemu_fdt_setprop_string(vms->fdt, nodename, "compatible", "cfi-flash");
        qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                     2, flashbase, 2, flashsize);
        qemu_fdt_setprop_cell(vms->fdt, nodename, "bank-width", 4);
        qemu_fdt_setprop_string(vms->fdt, nodename, "status", "disabled");
        qemu_fdt_setprop_string(vms->fdt, nodename, "secure-status", "okay");
        g_free(nodename);

        nodename = g_strdup_printf("/flash@%" PRIx64, flashbase);
        qemu_fdt_add_subnode(vms->fdt, nodename);
        qemu_fdt_setprop_string(vms->fdt, nodename, "compatible", "cfi-flash");
        qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                     2, flashbase + flashsize, 2, flashsize);
        qemu_fdt_setprop_cell(vms->fdt, nodename, "bank-width", 4);
        g_free(nodename);
    }
}

static FWCfgState *create_fw_cfg(const VirtMachineState *vms, AddressSpace *as)
{
    hwaddr base = vms->memmap[VIRT_FW_CFG].base;
    hwaddr size = vms->memmap[VIRT_FW_CFG].size;
    FWCfgState *fw_cfg;
    char *nodename;

    fw_cfg = fw_cfg_init_mem_wide(base + 8, base, 8, base + 16, as);
    fw_cfg_add_i16(fw_cfg, FW_CFG_NB_CPUS, (uint16_t)smp_cpus);

    nodename = g_strdup_printf("/fw-cfg@%" PRIx64, base);
    qemu_fdt_add_subnode(vms->fdt, nodename);
    qemu_fdt_setprop_string(vms->fdt, nodename,
                            "compatible", "qemu,fw-cfg-mmio");
    qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                 2, base, 2, size);
    qemu_fdt_setprop(vms->fdt, nodename, "dma-coherent", NULL, 0);
    g_free(nodename);
    return fw_cfg;
}

static void create_pcie_irq_map(const VirtMachineState *vms,
                                uint32_t gic_phandle,
                                int first_irq, const char *nodename)
{
    int devfn, pin;
    uint32_t full_irq_map[4 * 4 * 10] = { 0 };
    uint32_t *irq_map = full_irq_map;

    for (devfn = 0; devfn <= 0x18; devfn += 0x8) {
        for (pin = 0; pin < 4; pin++) {
            int irq_type = GIC_FDT_IRQ_TYPE_SPI;
            int irq_nr = first_irq + ((pin + PCI_SLOT(devfn)) % PCI_NUM_PINS);
            int irq_level = GIC_FDT_IRQ_FLAGS_LEVEL_HI;
            int i;

            uint32_t map[] = {
                devfn << 8, 0, 0,                           /* devfn */
                pin + 1,                                    /* PCI pin */
                gic_phandle, 0, 0, irq_type, irq_nr, irq_level }; /* GIC irq */

            /* Convert map to big endian */
            for (i = 0; i < 10; i++) {
                irq_map[i] = cpu_to_be32(map[i]);
            }
            irq_map += 10;
        }
    }

    qemu_fdt_setprop(vms->fdt, nodename, "interrupt-map",
                     full_irq_map, sizeof(full_irq_map));

    qemu_fdt_setprop_cells(vms->fdt, nodename, "interrupt-map-mask",
                           0x1800, 0, 0, /* devfn (PCI_SLOT(3)) */
                           0x7           /* PCI irq */);
}

static void create_pcie(const VirtMachineState *vms, qemu_irq *pic)
{
    hwaddr base_mmio = vms->memmap[VIRT_PCIE_MMIO].base;
    hwaddr size_mmio = vms->memmap[VIRT_PCIE_MMIO].size;
    hwaddr base_mmio_high = vms->memmap[VIRT_PCIE_MMIO_HIGH].base;
    hwaddr size_mmio_high = vms->memmap[VIRT_PCIE_MMIO_HIGH].size;
    hwaddr base_pio = vms->memmap[VIRT_PCIE_PIO].base;
    hwaddr size_pio = vms->memmap[VIRT_PCIE_PIO].size;
    hwaddr base_ecam = vms->memmap[VIRT_PCIE_ECAM].base;
    hwaddr size_ecam = vms->memmap[VIRT_PCIE_ECAM].size;
    hwaddr base = base_mmio;
    int nr_pcie_buses = size_ecam / PCIE_MMCFG_SIZE_MIN;
    int irq = vms->irqmap[VIRT_PCIE];
    MemoryRegion *mmio_alias;
    MemoryRegion *mmio_reg;
    MemoryRegion *ecam_alias;
    MemoryRegion *ecam_reg;
    DeviceState *dev;
    char *nodename;
    int i;
    PCIHostState *pci;

    dev = qdev_create(NULL, TYPE_GPEX_HOST);
    qdev_init_nofail(dev);

    /* Map only the first size_ecam bytes of ECAM space */
    ecam_alias = g_new0(MemoryRegion, 1);
    ecam_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    memory_region_init_alias(ecam_alias, OBJECT(dev), "pcie-ecam",
                             ecam_reg, 0, size_ecam);
    memory_region_add_subregion(get_system_memory(), base_ecam, ecam_alias);

    /* Map the MMIO window into system address space so as to expose
     * the section of PCI MMIO space which starts at the same base address
     * (ie 1:1 mapping for that part of PCI MMIO space visible through
     * the window).
     */
    mmio_alias = g_new0(MemoryRegion, 1);
    mmio_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 1);
    memory_region_init_alias(mmio_alias, OBJECT(dev), "pcie-mmio",
                             mmio_reg, base_mmio, size_mmio);
    memory_region_add_subregion(get_system_memory(), base_mmio, mmio_alias);

    if (vms->highmem) {
        /* Map high MMIO space */
        MemoryRegion *high_mmio_alias = g_new0(MemoryRegion, 1);

        memory_region_init_alias(high_mmio_alias, OBJECT(dev), "pcie-mmio-high",
                                 mmio_reg, base_mmio_high, size_mmio_high);
        memory_region_add_subregion(get_system_memory(), base_mmio_high,
                                    high_mmio_alias);
    }

    /* Map IO port space */
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 2, base_pio);

    for (i = 0; i < GPEX_NUM_IRQS; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), i, pic[irq + i]);
    }

    pci = PCI_HOST_BRIDGE(dev);
    if (pci->bus) {
        for (i = 0; i < nb_nics; i++) {
            NICInfo *nd = &nd_table[i];

            if (!nd->model) {
                nd->model = g_strdup("virtio");
            }

            pci_nic_init_nofail(nd, pci->bus, nd->model, NULL);
        }
    }

    nodename = g_strdup_printf("/pcie@%" PRIx64, base);
    qemu_fdt_add_subnode(vms->fdt, nodename);
    qemu_fdt_setprop_string(vms->fdt, nodename,
                            "compatible", "pci-host-ecam-generic");
    qemu_fdt_setprop_string(vms->fdt, nodename, "device_type", "pci");
    qemu_fdt_setprop_cell(vms->fdt, nodename, "#address-cells", 3);
    qemu_fdt_setprop_cell(vms->fdt, nodename, "#size-cells", 2);
    qemu_fdt_setprop_cells(vms->fdt, nodename, "bus-range", 0,
                           nr_pcie_buses - 1);
    qemu_fdt_setprop(vms->fdt, nodename, "dma-coherent", NULL, 0);

    if (vms->msi_phandle) {
        qemu_fdt_setprop_cells(vms->fdt, nodename, "msi-parent",
                               vms->msi_phandle);
    }

    qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg",
                                 2, base_ecam, 2, size_ecam);

    if (vms->highmem) {
        qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "ranges",
                                     1, FDT_PCI_RANGE_IOPORT, 2, 0,
                                     2, base_pio, 2, size_pio,
                                     1, FDT_PCI_RANGE_MMIO, 2, base_mmio,
                                     2, base_mmio, 2, size_mmio,
                                     1, FDT_PCI_RANGE_MMIO_64BIT,
                                     2, base_mmio_high,
                                     2, base_mmio_high, 2, size_mmio_high);
    } else {
        qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "ranges",
                                     1, FDT_PCI_RANGE_IOPORT, 2, 0,
                                     2, base_pio, 2, size_pio,
                                     1, FDT_PCI_RANGE_MMIO, 2, base_mmio,
                                     2, base_mmio, 2, size_mmio);
    }

    qemu_fdt_setprop_cell(vms->fdt, nodename, "#interrupt-cells", 1);
    create_pcie_irq_map(vms, vms->gic_phandle, irq, nodename);

    g_free(nodename);
}

static void create_platform_bus(VirtMachineState *vms, qemu_irq *pic)
{
    DeviceState *dev;
    SysBusDevice *s;
    int i;
    ARMPlatformBusFDTParams *fdt_params = g_new(ARMPlatformBusFDTParams, 1);
    MemoryRegion *sysmem = get_system_memory();

    platform_bus_params.platform_bus_base = vms->memmap[VIRT_PLATFORM_BUS].base;
    platform_bus_params.platform_bus_size = vms->memmap[VIRT_PLATFORM_BUS].size;
    platform_bus_params.platform_bus_first_irq = vms->irqmap[VIRT_PLATFORM_BUS];
    platform_bus_params.platform_bus_num_irqs = PLATFORM_BUS_NUM_IRQS;

    fdt_params->system_params = &platform_bus_params;
    fdt_params->binfo = &vms->bootinfo;
    fdt_params->intc = "/intc";
    /*
     * register a machine init done notifier that creates the device tree
     * nodes of the platform bus and its children dynamic sysbus devices
     */
    arm_register_platform_bus_fdt_creator(fdt_params);

    dev = qdev_create(NULL, TYPE_PLATFORM_BUS_DEVICE);
    dev->id = TYPE_PLATFORM_BUS_DEVICE;
    qdev_prop_set_uint32(dev, "num_irqs",
        platform_bus_params.platform_bus_num_irqs);
    qdev_prop_set_uint32(dev, "mmio_size",
        platform_bus_params.platform_bus_size);
    qdev_init_nofail(dev);
    s = SYS_BUS_DEVICE(dev);

    for (i = 0; i < platform_bus_params.platform_bus_num_irqs; i++) {
        int irqn = platform_bus_params.platform_bus_first_irq + i;
        sysbus_connect_irq(s, i, pic[irqn]);
    }

    memory_region_add_subregion(sysmem,
                                platform_bus_params.platform_bus_base,
                                sysbus_mmio_get_region(s, 0));
}

static void create_secure_ram(VirtMachineState *vms,
                              MemoryRegion *secure_sysmem)
{
    MemoryRegion *secram = g_new(MemoryRegion, 1);
    char *nodename;
    hwaddr base = vms->memmap[VIRT_SECURE_MEM].base;
    hwaddr size = vms->memmap[VIRT_SECURE_MEM].size;

    memory_region_init_ram(secram, NULL, "virt.secure-ram", size, &error_fatal);
    vmstate_register_ram_global(secram);
    memory_region_add_subregion(secure_sysmem, base, secram);

    nodename = g_strdup_printf("/secram@%" PRIx64, base);
    qemu_fdt_add_subnode(vms->fdt, nodename);
    qemu_fdt_setprop_string(vms->fdt, nodename, "device_type", "memory");
    qemu_fdt_setprop_sized_cells(vms->fdt, nodename, "reg", 2, base, 2, size);
    qemu_fdt_setprop_string(vms->fdt, nodename, "status", "disabled");
    qemu_fdt_setprop_string(vms->fdt, nodename, "secure-status", "okay");

    g_free(nodename);
}

static void *machvirt_dtb(const struct arm_boot_info *binfo, int *fdt_size)
{
    const VirtMachineState *board = container_of(binfo, VirtMachineState,
                                                 bootinfo);

    *fdt_size = board->fdt_size;
    return board->fdt;
}

static void virt_build_smbios(VirtMachineState *vms)
{
    uint8_t *smbios_tables, *smbios_anchor;
    size_t smbios_tables_len, smbios_anchor_len;
    const char *product = "QEMU Virtual Machine";

    if (!vms->fw_cfg) {
        return;
    }

    if (kvm_enabled()) {
        product = "KVM Virtual Machine";
    }

    smbios_set_defaults("QEMU", product,
                        "1.0", false, true, SMBIOS_ENTRY_POINT_30);

    smbios_get_tables(NULL, 0, &smbios_tables, &smbios_tables_len,
                      &smbios_anchor, &smbios_anchor_len);

    if (smbios_anchor) {
        fw_cfg_add_file(vms->fw_cfg, "etc/smbios/smbios-tables",
                        smbios_tables, smbios_tables_len);
        fw_cfg_add_file(vms->fw_cfg, "etc/smbios/smbios-anchor",
                        smbios_anchor, smbios_anchor_len);
    }
}

static
void virt_machine_done(Notifier *notifier, void *data)
{
    VirtMachineState *vms = container_of(notifier, VirtMachineState,
                                         machine_done);

    virt_acpi_setup(vms);
    virt_build_smbios(vms);
}

static void machvirt_init(MachineState *machine)
{
    VirtMachineState *vms = VIRT_MACHINE(machine);
    VirtMachineClass *vmc = VIRT_MACHINE_GET_CLASS(machine);
    qemu_irq pic[NUM_IRQS];
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *secure_sysmem = NULL;
    int n, virt_max_cpus;
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    const char *cpu_model = machine->cpu_model;
    char **cpustr;
    ObjectClass *oc;
    const char *typename;
    CPUClass *cc;
    Error *err = NULL;
    bool firmware_loaded = bios_name || drive_get(IF_PFLASH, 0, 0);
    uint8_t clustersz;

    if (!cpu_model) {
        cpu_model = "cortex-a15";
    }

    /* We can probe only here because during property set
     * KVM is not available yet
     */
    if (!vms->gic_version) {
        if (!kvm_enabled()) {
            error_report("gic-version=host requires KVM");
            exit(1);
        }

        vms->gic_version = kvm_arm_vgic_probe();
        if (!vms->gic_version) {
            error_report("Unable to determine GIC version supported by host");
            exit(1);
        }
    }

    /* Separate the actual CPU model name from any appended features */
    cpustr = g_strsplit(cpu_model, ",", 2);

    if (!cpuname_valid(cpustr[0])) {
        error_report("mach-virt: CPU %s not supported", cpustr[0]);
        exit(1);
    }

    /* If we have an EL3 boot ROM then the assumption is that it will
     * implement PSCI itself, so disable QEMU's internal implementation
     * so it doesn't get in the way. Instead of starting secondary
     * CPUs in PSCI powerdown state we will start them all running and
     * let the boot ROM sort them out.
     * The usual case is that we do use QEMU's PSCI implementation;
     * if the guest has EL2 then we will use SMC as the conduit,
     * and otherwise we will use HVC (for backwards compatibility and
     * because if we're using KVM then we must use HVC).
     */
    if (vms->secure && firmware_loaded) {
        vms->psci_conduit = QEMU_PSCI_CONDUIT_DISABLED;
    } else if (vms->virt) {
        vms->psci_conduit = QEMU_PSCI_CONDUIT_SMC;
    } else {
        vms->psci_conduit = QEMU_PSCI_CONDUIT_HVC;
    }

    /* The maximum number of CPUs depends on the GIC version, or on how
     * many redistributors we can fit into the memory map.
     */
    if (vms->gic_version == 3) {
        virt_max_cpus = vms->memmap[VIRT_GIC_REDIST].size / 0x20000;
        clustersz = GICV3_TARGETLIST_BITS;
    } else {
        virt_max_cpus = GIC_NCPU;
        clustersz = GIC_TARGETLIST_BITS;
    }

    if (max_cpus > virt_max_cpus) {
        error_report("Number of SMP CPUs requested (%d) exceeds max CPUs "
                     "supported by machine 'mach-virt' (%d)",
                     max_cpus, virt_max_cpus);
        exit(1);
    }

    vms->smp_cpus = smp_cpus;

    if (machine->ram_size > vms->memmap[VIRT_MEM].size) {
        error_report("mach-virt: cannot model more than %dGB RAM", RAMLIMIT_GB);
        exit(1);
    }

    if (vms->virt && kvm_enabled()) {
        error_report("mach-virt: KVM does not support providing "
                     "Virtualization extensions to the guest CPU");
        exit(1);
    }

    if (vms->secure) {
        if (kvm_enabled()) {
            error_report("mach-virt: KVM does not support Security extensions");
            exit(1);
        }

        /* The Secure view of the world is the same as the NonSecure,
         * but with a few extra devices. Create it as a container region
         * containing the system memory at low priority; any secure-only
         * devices go in at higher priority and take precedence.
         */
        secure_sysmem = g_new(MemoryRegion, 1);
        memory_region_init(secure_sysmem, OBJECT(machine), "secure-memory",
                           UINT64_MAX);
        memory_region_add_subregion_overlap(secure_sysmem, 0, sysmem, -1);
    }

    create_fdt(vms);

    oc = cpu_class_by_name(TYPE_ARM_CPU, cpustr[0]);
    if (!oc) {
        error_report("Unable to find CPU definition");
        exit(1);
    }
    typename = object_class_get_name(oc);

    /* convert -smp CPU options specified by the user into global props */
    cc = CPU_CLASS(oc);
    cc->parse_features(typename, cpustr[1], &err);
    g_strfreev(cpustr);
    if (err) {
        error_report_err(err);
        exit(1);
    }

    for (n = 0; n < smp_cpus; n++) {
        Object *cpuobj = object_new(typename);
        if (!vmc->disallow_affinity_adjustment) {
            /* Adjust MPIDR like 64-bit KVM hosts, which incorporate the
             * GIC's target-list limitations. 32-bit KVM hosts currently
             * always create clusters of 4 CPUs, but that is expected to
             * change when they gain support for gicv3. When KVM is enabled
             * it will override the changes we make here, therefore our
             * purposes are to make TCG consistent (with 64-bit KVM hosts)
             * and to improve SGI efficiency.
             */
            uint8_t aff1 = n / clustersz;
            uint8_t aff0 = n % clustersz;
            object_property_set_int(cpuobj, (aff1 << ARM_AFF1_SHIFT) | aff0,
                                    "mp-affinity", NULL);
        }

        if (!vms->secure) {
            object_property_set_bool(cpuobj, false, "has_el3", NULL);
        }

        if (!vms->virt && object_property_find(cpuobj, "has_el2", NULL)) {
            object_property_set_bool(cpuobj, false, "has_el2", NULL);
        }

        if (vms->psci_conduit != QEMU_PSCI_CONDUIT_DISABLED) {
            object_property_set_int(cpuobj, vms->psci_conduit,
                                    "psci-conduit", NULL);

            /* Secondary CPUs start in PSCI powered-down state */
            if (n > 0) {
                object_property_set_bool(cpuobj, true,
                                         "start-powered-off", NULL);
            }
        }

        if (vmc->no_pmu && object_property_find(cpuobj, "pmu", NULL)) {
            object_property_set_bool(cpuobj, false, "pmu", NULL);
        }

        if (object_property_find(cpuobj, "reset-cbar", NULL)) {
            object_property_set_int(cpuobj, vms->memmap[VIRT_CPUPERIPHS].base,
                                    "reset-cbar", &error_abort);
        }

        object_property_set_link(cpuobj, OBJECT(sysmem), "memory",
                                 &error_abort);
        if (vms->secure) {
            object_property_set_link(cpuobj, OBJECT(secure_sysmem),
                                     "secure-memory", &error_abort);
        }

        object_property_set_bool(cpuobj, true, "realized", NULL);
        object_unref(cpuobj);
    }
    fdt_add_timer_nodes(vms);
    fdt_add_cpu_nodes(vms);
    fdt_add_psci_node(vms);

    memory_region_allocate_system_memory(ram, NULL, "mach-virt.ram",
                                         machine->ram_size);
    memory_region_add_subregion(sysmem, vms->memmap[VIRT_MEM].base, ram);

    create_flash(vms, sysmem, secure_sysmem ? secure_sysmem : sysmem);

    create_gic(vms, pic);

    fdt_add_pmu_nodes(vms);

    create_uart(vms, pic, VIRT_UART0, sysmem, serial_hds[0]);
    create_uart(vms, pic, VIRT_UART1, sysmem, serial_hds[1]);
    create_uart(vms, pic, VIRT_UART2, sysmem, serial_hds[2]);
    create_uart(vms, pic, VIRT_UART3, sysmem, serial_hds[3]);

    if (vms->secure) {
        create_secure_ram(vms, secure_sysmem);
        create_uart(vms, pic, VIRT_SECURE_UART, secure_sysmem, serial_hds[4]);
    }

    create_rtc(vms, pic);

    create_pcie(vms, pic);

    create_gpio(vms, pic);

    /* Create mmio transports, so the user can create virtio backends
     * (which will be automatically plugged in to the transports). If
     * no backend is created the transport will just sit harmlessly idle.
     */
    create_virtio_devices(vms, pic);

    vms->fw_cfg = create_fw_cfg(vms, &address_space_memory);
    rom_set_fw(vms->fw_cfg);

    vms->machine_done.notify = virt_machine_done;
    qemu_add_machine_init_done_notifier(&vms->machine_done);

    vms->bootinfo.ram_size = machine->ram_size;
    vms->bootinfo.kernel_filename = machine->kernel_filename;
    vms->bootinfo.kernel_cmdline = machine->kernel_cmdline;
    vms->bootinfo.initrd_filename = machine->initrd_filename;
    vms->bootinfo.nb_cpus = smp_cpus;
    vms->bootinfo.board_id = -1;
    vms->bootinfo.loader_start = vms->memmap[VIRT_MEM].base;
    vms->bootinfo.get_dtb = machvirt_dtb;
    vms->bootinfo.firmware_loaded = firmware_loaded;
    arm_load_kernel(ARM_CPU(first_cpu), &vms->bootinfo);

    /*
     * arm_load_kernel machine init done notifier registration must
     * happen before the platform_bus_create call. In this latter,
     * another notifier is registered which adds platform bus nodes.
     * Notifiers are executed in registration reverse order.
     */
    create_platform_bus(vms, pic);
}

static bool virt_get_secure(Object *obj, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    return vms->secure;
}

static void virt_set_secure(Object *obj, bool value, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    vms->secure = value;
}

static bool virt_get_virt(Object *obj, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    return vms->virt;
}

static void virt_set_virt(Object *obj, bool value, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    vms->virt = value;
}

static bool virt_get_highmem(Object *obj, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    return vms->highmem;
}

static void virt_set_highmem(Object *obj, bool value, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    vms->highmem = value;
}

static bool virt_get_its(Object *obj, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    return vms->its;
}

static void virt_set_its(Object *obj, bool value, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    vms->its = value;
}

static char *virt_get_gic_version(Object *obj, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);
    const char *val = vms->gic_version == 3 ? "3" : "2";

    return g_strdup(val);
}

static void virt_set_gic_version(Object *obj, const char *value, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);

    if (!strcmp(value, "3")) {
        vms->gic_version = 3;
    } else if (!strcmp(value, "2")) {
        vms->gic_version = 2;
    } else if (!strcmp(value, "host")) {
        vms->gic_version = 0; /* Will probe later */
    } else {
        error_setg(errp, "Invalid gic-version value");
        error_append_hint(errp, "Valid values are 3, 2, host.\n");
    }
}

static void virt_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->init = machvirt_init;
    /* Start max_cpus at the maximum QEMU supports. We'll further restrict
     * it later in machvirt_init, where we have more information about the
     * configuration of the particular instance.
     */
    mc->max_cpus = 255;
    mc->has_dynamic_sysbus = true;
    mc->block_default_type = IF_VIRTIO;
    mc->no_cdrom = 1;
    mc->pci_allow_0_address = true;
    /* We know we will never create a pre-ARMv7 CPU which needs 1K pages */
    mc->minimum_page_bits = 12;
}

static const TypeInfo virt_machine_info = {
    .name          = TYPE_VIRT_MACHINE,
    .parent        = TYPE_MACHINE,
    .abstract      = true,
    .instance_size = sizeof(VirtMachineState),
    .class_size    = sizeof(VirtMachineClass),
    .class_init    = virt_machine_class_init,
};

static void machvirt_machine_init(void)
{
    type_register_static(&virt_machine_info);
}
type_init(machvirt_machine_init);

static void virt_2_9_instance_init(Object *obj)
{
    VirtMachineState *vms = VIRT_MACHINE(obj);
    VirtMachineClass *vmc = VIRT_MACHINE_GET_CLASS(vms);

    /* EL3 is disabled by default on virt: this makes us consistent
     * between KVM and TCG for this board, and it also allows us to
     * boot UEFI blobs which assume no TrustZone support.
     */
    vms->secure = false;
    object_property_add_bool(obj, "secure", virt_get_secure,
                             virt_set_secure, NULL);
    object_property_set_description(obj, "secure",
                                    "Set on/off to enable/disable the ARM "
                                    "Security Extensions (TrustZone)",
                                    NULL);

    /* EL2 is also disabled by default, for similar reasons */
    vms->virt = false;
    object_property_add_bool(obj, "virtualization", virt_get_virt,
                             virt_set_virt, NULL);
    object_property_set_description(obj, "virtualization",
                                    "Set on/off to enable/disable emulating a "
                                    "guest CPU which implements the ARM "
                                    "Virtualization Extensions",
                                    NULL);

    /* High memory is enabled by default */
    vms->highmem = true;
    object_property_add_bool(obj, "highmem", virt_get_highmem,
                             virt_set_highmem, NULL);
    object_property_set_description(obj, "highmem",
                                    "Set on/off to enable/disable using "
                                    "physical address space above 32 bits",
                                    NULL);
    /* Default GIC type is v2 */
    vms->gic_version = 2;
    object_property_add_str(obj, "gic-version", virt_get_gic_version,
                        virt_set_gic_version, NULL);
    object_property_set_description(obj, "gic-version",
                                    "Set GIC version. "
                                    "Valid values are 2, 3 and host", NULL);

    if (vmc->no_its) {
        vms->its = false;
    } else {
        /* Default allows ITS instantiation */
        vms->its = true;
        object_property_add_bool(obj, "its", virt_get_its,
                                 virt_set_its, NULL);
        object_property_set_description(obj, "its",
                                        "Set on/off to enable/disable "
                                        "ITS instantiation",
                                        NULL);
    }

    vms->memmap = a15memmap;
    vms->irqmap = a15irqmap;
}

static void virt_machine_2_9_options(MachineClass *mc)
{
}
DEFINE_VIRT_MACHINE_AS_LATEST(2, 9)

#define VIRT_COMPAT_2_8 \
    HW_COMPAT_2_8

static void virt_2_8_instance_init(Object *obj)
{
    virt_2_9_instance_init(obj);
}

static void virt_machine_2_8_options(MachineClass *mc)
{
    VirtMachineClass *vmc = VIRT_MACHINE_CLASS(OBJECT_CLASS(mc));

    virt_machine_2_9_options(mc);
    SET_MACHINE_COMPAT(mc, VIRT_COMPAT_2_8);
    /* For 2.8 and earlier we falsely claimed in the DT that
     * our timers were edge-triggered, not level-triggered.
     */
    vmc->claim_edge_triggered_timers = true;
}
DEFINE_VIRT_MACHINE(2, 8)

#define VIRT_COMPAT_2_7 \
    HW_COMPAT_2_7

static void virt_2_7_instance_init(Object *obj)
{
    virt_2_8_instance_init(obj);
}

static void virt_machine_2_7_options(MachineClass *mc)
{
    VirtMachineClass *vmc = VIRT_MACHINE_CLASS(OBJECT_CLASS(mc));

    virt_machine_2_8_options(mc);
    SET_MACHINE_COMPAT(mc, VIRT_COMPAT_2_7);
    /* ITS was introduced with 2.8 */
    vmc->no_its = true;
    /* Stick with 1K pages for migration compatibility */
    mc->minimum_page_bits = 0;
}
DEFINE_VIRT_MACHINE(2, 7)

#define VIRT_COMPAT_2_6 \
    HW_COMPAT_2_6

static void virt_2_6_instance_init(Object *obj)
{
    virt_2_7_instance_init(obj);
}

static void virt_machine_2_6_options(MachineClass *mc)
{
    VirtMachineClass *vmc = VIRT_MACHINE_CLASS(OBJECT_CLASS(mc));

    virt_machine_2_7_options(mc);
    SET_MACHINE_COMPAT(mc, VIRT_COMPAT_2_6);
    vmc->disallow_affinity_adjustment = true;
    /* Disable PMU for 2.6 as PMU support was first introduced in 2.7 */
    vmc->no_pmu = true;
}
DEFINE_VIRT_MACHINE(2, 6)
