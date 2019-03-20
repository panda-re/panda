#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/arm/arm.h"
#include "hw/arm/primecell.h"
#include "hw/arm/rehosting.h"
#include "hw/cpu/a9mpcore.h"
#include "hw/cpu/a15mpcore.h"
#include "hw/devices.h"
#include "net/net.h"
#include "sysemu/block-backend.h"
#include "sysemu/device_tree.h"
#include "sysemu/numa.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "hw/boards.h"
#include "hw/compat.h"
#include "hw/loader.h"
#include "exec/address-spaces.h"
#include "exec/hwaddr.h"
#include "qemu/bitops.h"
#include "qemu/error-report.h"
#include "hw/pci-host/gpex.h"
#include "hw/intc/arm_gic_common.h"
#include "kvm_arm.h"
#include "hw/smbios/smbios.h"
#include "qapi/visitor.h"
#include "standard-headers/linux/input.h"
#include "qemu/config-file.h"
#include "hw/arm/fdt.h"

/*
 * Main board type
 */
extern void panda_callbacks_during_machine_init(void);

typedef struct RehostingBoardInfo {
    struct arm_boot_info bootinfo;
    const char *cpu_model;
    const MemMapEntry *dev_mem_map;
    const MemMapEntry *file_mem_map;
    const int *irqmap;
    int smp_cpus;
    void *fdt;
    int fdt_size;
    uint32_t clock_phandle;
    uint32_t gic_phandle;
    uint32_t v2m_phandle;
    bool using_psci;
} RehostingBoardInfo;

typedef struct {
    MachineClass parent;
    RehostingBoardInfo *daughterboard;
} RehostingMachineClass;


#define TYPE_REHOSTING_MACHINE   MACHINE_TYPE_NAME("Rehosting")
#define REHOSTING_MACHINE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(RehostingMachineClass, obj, TYPE_REHOSTING_MACHINE)
#define REHOSTING_MACHINE_CLASS(klass) \
    OBJECT_CLASS_CHECK(RehostingMachineClass, klass, TYPE_REHOSTING_MACHINE)

static MemMapEntry dev_mem_map[MEM_REGION_COUNT];
static MemMapEntry file_mem_map[MAX_MEM_MAPPED_FILES];

// Allocate enough for both SPI and PPI IRQs
static int irqmap[NUM_IRQS +
    (GIC_NR_SGIS * REHOSTING_MAX_CPUS) +
    ((GIC_INTERNAL - GIC_NR_SGIS) * REHOSTING_MAX_CPUS)];

typedef struct {
    QEMUTimer *timer;
    qemu_irq sgi[REHOSTING_MAX_CPUS][GIC_NR_SGIS];                  // Software Generated Interrupts (SGI)
    qemu_irq ppi[REHOSTING_MAX_CPUS][(GIC_INTERNAL - GIC_NR_SGIS)]; // Shared Peripheral Interrupts (SPI)
    qemu_irq spi[NUM_IRQS];                                         // Private Peripheral Interrupts (PPI)
} machine_irqs;

static long int get_file_size(char file_name[]) {

    long int size;
    FILE* fp = fopen(file_name, "r");

    if (fp == NULL) {
        RH_DBG("File %s not found!", file_name);
        return -1;
    }

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fclose(fp);

    return size;

}

static void parse_mem_map(char *map_str)
{
    static int fmm_idx = 0;

    if (!map_str) {
        error_report("No memory map specified!");
        return;
    }

    // Format is "REGION_NAME 0xstart-0xend;..." or "FILE_PATH 0xstart-0xend;..."
    char *pos = strtok(map_str, ";");
    while (pos) {
        char name[MAX_NAME_LEN];
        int type;
        hwaddr start, end;
        struct stat st;
        char* fn;
        long int fs;

        if (sscanf(pos, "%" STR(MAX_NAME_LEN) "s %lx-%lx", name, &start, &end) == 3) {

            /*
             * "Dynamically" create memory regions for QEMU's implemented devices or
             * for memory-mapped files
             */

            // File mapping
            if (stat(name, &st) >= 0) {

                if (fmm_idx < MAX_MEM_MAPPED_FILES) {
                    fn = g_malloc0(strlen(name) + 1);
                    assert(fn != NULL);
                    strncpy(fn, name, (strlen(name)+1));
                    fs = get_file_size(name);
                    if (fs != -1) {
                        file_mem_map[fmm_idx].base = start;
                        file_mem_map[fmm_idx].size = fs;
                        file_mem_map[fmm_idx].opt_fn_str = fn;
                        fmm_idx++;
                    } else {
                        free(fn);
                        error_report("Couldn't get filesize for %s", name);
                        pos = strtok(NULL, ";");
                        continue;
                    }
                } else {
                    RH_DBG("Mapped file limit reached! Ignoring %s", name);
                    pos = strtok(NULL, ";");
                    continue;
                }

            // Device mapping
            } else {
                if (strcmp(name, "MEM") == 0)
                    type = MEM;
                else if (strcmp(name, "NAND") == 0)
                    type = NAND;
                else if (strcmp(name, "DMAC") == 0)
                    type = DMAC;
                else if (strcmp(name, "GIC_DIST") == 0)
                    type = GIC_DIST;
                else if (strcmp(name, "GIC_CPU") == 0)
                    type = GIC_CPU;
                else if (strcmp(name, "GIC_V2M") == 0)
                    type = GIC_V2M;
                else if (strcmp(name, "GIC_ITS") == 0)
                    type = GIC_ITS;
                else if (strcmp(name, "GIC_REDIST") == 0)
                    type = GIC_REDIST;
                else if (strcmp(name, "MPCORE_PERIPHBASE") == 0)
                    type = MPCORE_PERIPHBASE;
                else if (strcmp(name, "CACHE_CTRL") == 0)
                    type = CACHE_CTRL;
                else if (strcmp(name, "VIRT_MMIO") == 0)
                    type = VIRT_MMIO;
                else {
                    error_report("Region '%s' doesn't exist", name);
                    pos = strtok(NULL, ";");
                    continue;
                }

                RH_DBG("Adding region: %s @ 0x%lx-0x%lx", name, start, end);

                dev_mem_map[type].base = start;
                dev_mem_map[type].size = (end - start);
            }
        } else {
            error_report("Error parsing memory region definition '%s'", pos);
        }
        pos = strtok(NULL, ";");
    }
}

// Match CPU model to GIC version number using a static lookup table defined in rehosting.h
static int lookup_gic(const char *cpu_model) {

    int i;

    for (i = 0; i < TABLE_CPU_TO_GIC_ENTRIES; i++) {
        if (strcmp(cpu_model, table_cpu_to_gic[i].entry_str) == 0) {
            return table_cpu_to_gic[i].entry_val;
        }
    }
    return -1;

}

static void debug_print_sysbus_dev_ranges(SysBusDevice *s) {

    hwaddr size;
    int i;

    for (i = 0; i < s->num_mmio; i++) {
        size = memory_region_size(s->mmio[i].memory);
        RH_DBG("MMIO: 0x%08lx - 0x%08lx",
            (long unsigned int)s->mmio[i].addr,
            (long unsigned int)(s->mmio[i].addr + size));
    }
}

/*
// Invariant checks on the state of bus devices, ie.
// TODO: Implement this
static void check_sysbus_invariants() {

    // TODO: how to implement?

    // What functions from sysbus.c?
    // sysbus_has_irq
    // sysbus_is_irq_connected
    // sys_bus_has_mmio


}
*/

static void create_internal_gic(RehostingBoardInfo *vbi, machine_irqs *irqs, int gic_version)
{
    // TODO: need to make use of sysbus_pass_irq?
    // TODO: need to call a9mp_priv_set_irq?

    DeviceState *dev;
    SysBusDevice *busdev;
    int i;
    long unsigned int gic_dist_addr, gic_cpu_addr;

    // CPU's private memory region and internal GIC
    if (strcmp(vbi->cpu_model, "cortex-a9") == 0) {

        // From hw/cpu/a9mpcore.c
        /* Memory map (addresses are offsets from PERIPHBASE):
        *  0x0000-0x00ff -- Snoop Control Unit
        *  0x0100-0x01ff -- GIC CPU interface
        *  0x0200-0x02ff -- Global Timer
        *  0x0300-0x05ff -- nothing
        *  0x0600-0x06ff -- private timers and watchdogs
        *  0x0700-0x0fff -- nothing
        *  0x1000-0x1fff -- GIC Distributor
        */
        dev = qdev_create(NULL, TYPE_A9MPCORE_PRIV);
        gic_dist_addr = (vbi->dev_mem_map[MPCORE_PERIPHBASE].base + 0x1000);
        gic_cpu_addr = (vbi->dev_mem_map[MPCORE_PERIPHBASE].base + 0x100);

    } else if (strcmp(vbi->cpu_model, "cortex-a15") == 0) {

        // From hw/cpu/a15mpcore.c
        /* Memory map (addresses are offsets from MPCORE_PERIPHBASE):
        *  0x0000-0x0fff -- reserved
        *  0x1000-0x1fff -- GIC Distributor
        *  0x2000-0x3fff -- GIC CPU interface
        *  0x4000-0x4fff -- GIC virtual interface control (not modelled)
        *  0x5000-0x5fff -- GIC virtual interface control (not modelled)
        *  0x6000-0x7fff -- GIC virtual CPU interface (not modelled)
        */
        dev = qdev_create(NULL, TYPE_A15MPCORE_PRIV);
        gic_dist_addr = (vbi->dev_mem_map[MPCORE_PERIPHBASE].base + 0x1000);
        gic_cpu_addr = (vbi->dev_mem_map[MPCORE_PERIPHBASE].base + 0x2000);

    } else {
        error_report("Rehosting machine doesn't currently support peripheral base for %s", vbi->cpu_model);
        exit(1);
    }

    vbi->bootinfo.gic_cpu_if_addr = gic_cpu_addr;
    RH_DBG("Adding GICv%i w/ %i IRQs: GIC_DIST @ 0x%08lx, GIC_CPU @ 0x%08lx", gic_version, NUM_IRQS, gic_dist_addr, gic_cpu_addr);

    qdev_prop_set_uint32(dev, "num-cpu", smp_cpus);
    qdev_prop_set_uint32(dev, "num-irq", NUM_IRQS);
    qdev_init_nofail(dev);
    busdev = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(busdev, 0, vbi->dev_mem_map[MPCORE_PERIPHBASE].base);
    debug_print_sysbus_dev_ranges(busdev);

    for (i = 0; i < smp_cpus; i++) {

        DeviceState *cpudev = DEVICE(qemu_get_cpu(i));

        //TODO: below should be wired internally?
        //int ppibase = NUM_IRQS + i * GIC_INTERNAL + GIC_NR_SGIS;
        //int ppibase = (NUM_IRQS - 32) + i * 32;
        int irq;

        // SGIs: 0-15
        for (irq = 0; irq < (GIC_INTERNAL - GIC_NR_SGIS); irq++) {
            //irqs->sgi[i][irq] = qdev_get_gpio_in(dev, ppibase + irq);
            irqs->sgi[i][irq] = qdev_get_gpio_in(dev, irq);
        }

        // PPIs: 16-31
        for (irq = GIC_NR_SGIS; irq < GIC_INTERNAL; irq++) {
            //irqs->ppi[i][irq] = qdev_get_gpio_in(dev, ppibase + irq);
            irqs->ppi[i][irq] = qdev_get_gpio_in(dev, irq);
        }

        // Wire GIC IRQ/FIQ to CPU inputs
        sysbus_connect_irq(busdev, i, qdev_get_gpio_in(cpudev, ARM_CPU_IRQ));
        sysbus_connect_irq(busdev, i + smp_cpus, qdev_get_gpio_in(cpudev, ARM_CPU_FIQ));
    }

    // SPIs: 31-NUM_IRQs by ID, 0-(NUM_IRQS - GIC_INTERNAL) by index
    for (i = 0; i < (NUM_IRQS - GIC_INTERNAL); i++) {
        irqs->spi[i] = qdev_get_gpio_in(dev, i);
    }
}

static void create_external_gic(RehostingBoardInfo *vbi, machine_irqs *irqs, int gic_version, bool secure)
{
    DeviceState *gicdev;
    SysBusDevice *gicbusdev;
    int i;

    // TODO: support GICv3 at somepoint
    if (gic_version == 3) {
        error_report("Rehosting machine doesn't currently support GICv3!");
        exit(1);
    }

    // Init GIC
    gicdev = qdev_create(NULL, gic_class_name());
    qdev_prop_set_uint32(gicdev, "revision", gic_version);
    qdev_prop_set_uint32(gicdev, "num-cpu", smp_cpus);
    /* Note that the num-irq property counts both internal and external
     * interrupts; there are always 32 of the former (mandated by GIC spec).
     */
    qdev_prop_set_uint32(gicdev, "num-irq", NUM_IRQS + 32);
    qdev_prop_set_bit(gicdev, "has-security-extensions", secure);
    qdev_init_nofail(gicdev);

    // Memory map GIC
    gicbusdev = SYS_BUS_DEVICE(gicdev);

    if (vbi->dev_mem_map[GIC_DIST].size) {
        sysbus_mmio_map(gicbusdev, 0, vbi->dev_mem_map[GIC_DIST].base);
    }

    if (vbi->dev_mem_map[GIC_CPU].size) {
        sysbus_mmio_map(gicbusdev, 1, vbi->dev_mem_map[GIC_CPU].base);
    }

    debug_print_sysbus_dev_ranges(gicbusdev);

    /* Wire the outputs from each CPU's generic timer and the GICv3
     * maintenance interrupt signal to the appropriate GIC PPI inputs,
     * and the GIC's IRQ/FIQ/VIRQ/VFIQ interrupt outputs to the CPU's inputs.
     */
    for (i = 0; i < smp_cpus; i++) {

        int ppibase = NUM_IRQS + i * GIC_INTERNAL + GIC_NR_SGIS;
        int irq;
        for (irq = 0; irq < (GIC_INTERNAL - GIC_NR_SGIS); irq++) {
            irqs->ppi[i][irq] = qdev_get_gpio_in(gicdev, ppibase + irq);
        }

        // Wire GIC IRQ/FIQ to CPU inputs
        DeviceState *cpudev = DEVICE(qemu_get_cpu(i));
        sysbus_connect_irq(gicbusdev, i, qdev_get_gpio_in(cpudev, ARM_CPU_IRQ));
        sysbus_connect_irq(gicbusdev, i + smp_cpus, qdev_get_gpio_in(cpudev, ARM_CPU_FIQ));
    }

    // Setup SPIs
    for (i = 0; i < NUM_IRQS; i++) {
        irqs->spi[i] = qdev_get_gpio_in(gicdev, i);
    }
}

// See: https://github.com/qemu/qemu/blob/a2e002ff7913ce93aa0f7dbedd2123dce5f1a9cd/hw/arm/virt.c#L883
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
        // Note this QEMU_FILE_TYPE_BIOS is used for fallback behavior, should not affect mounting rootfs
        fn = qemu_find_file(QEMU_FILE_TYPE_BIOS, file);
        if (!fn) {
            error_report("Could not find drive image '%s'", file);
            exit(1);
        }
        image_size = load_image_mr(fn, sysbus_mmio_get_region(sbd, 0));
        g_free(fn);
        if (image_size < 0) {
            error_report("Could not load drive image '%s'", file);
            exit(1);
        }
    }
}

// https://github.com/qemu/qemu/blob/a2e002ff7913ce93aa0f7dbedd2123dce5f1a9cd/hw/arm/virt.c#L805
static void create_virtio_devices(RehostingBoardInfo *vbi, qemu_irq *pic)
{
    int i;
    hwaddr size = vbi->dev_mem_map[VIRT_MMIO].size;

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

        int irq = vbi->irqmap[VIRT_MMIO] + i;
        hwaddr base = vbi->dev_mem_map[VIRT_MMIO].base + i * size;

        RH_DBG("Adding VIRTO_MMIO IRQ: %x", irq);
        sysbus_create_simple("virtio-mmio", base, pic[irq]);

        // NOTE: we do dtb modifications in 'dtb.py' if add_virt_mmio_node() is called!

    }
}

static void mach_rehosting_init(MachineState *machine)
{
    
    panda_callbacks_during_machine_init();
    machine_irqs *s = g_malloc0(sizeof(machine_irqs));
    MemoryRegion *sysmem = get_system_memory();
    int gic_version = 2;
    int n;
    int temp;
    RehostingBoardInfo *vbi;
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    bool firmware_loaded = bios_name || drive_get(IF_PFLASH, 0, 0);

    vbi = g_malloc0(sizeof(RehostingBoardInfo));
    vbi->cpu_model = machine->cpu_model;

    assert(vbi != NULL);
    assert(s != NULL);

    if (!vbi->cpu_model) {
        vbi->cpu_model = "cortex-a15";
    }

    if ((temp = lookup_gic(vbi->cpu_model)) != -1) {
        gic_version = temp;
    }

    vbi->dev_mem_map = dev_mem_map;
    vbi->file_mem_map = file_mem_map;
    vbi->irqmap = irqmap;

    // Zero-init structs before parsing
    for (int i = 0; i < MAX_MEM_MAPPED_FILES; i++) {
        file_mem_map[i].opt_fn_str = NULL;
        file_mem_map[i].base = 0;
        file_mem_map[i].size = 0;
    }

    for (int i = 0; i < MEM_REGION_COUNT; i++) {
        dev_mem_map[i].opt_fn_str = NULL;
        dev_mem_map[i].base = 0;
        dev_mem_map[i].size = 0;
    }

//    parse_mem_map(machine->mem_map_str);
    char mem_str[] = "VIRT_MMIO 0a000000-0a000200;CACHE_CTRL f1008000-f1009000;MPCORE_PERIPHBASE f100c000-f100e000;MEM 00000000-40000000";
    parse_mem_map(mem_str);
    vbi->smp_cpus = smp_cpus;

    // Init CPUs
    for (n = 0; n < smp_cpus; n++) {
        ObjectClass *cpu_oc = cpu_class_by_name(TYPE_ARM_CPU, vbi->cpu_model);
        Object *cpuobj;

        if (!cpu_oc) {
            error_report("Unable to find CPU definition");
            exit(1);
        } else {
            RH_DBG("Adding CPU: %s (%i of %i)", vbi->cpu_model, (n + 1), smp_cpus);
        }

        cpuobj = object_new(object_class_get_name(cpu_oc));

        // Disable TrustZone
        if (object_property_find(cpuobj, "has_el3", NULL)) {
            object_property_set_bool(cpuobj, false, "has_el3", &error_abort);
        }

        // Setup CBAR
        if (object_property_find(cpuobj, "reset-cbar", NULL) && vbi->dev_mem_map[MPCORE_PERIPHBASE].base) {
            object_property_set_int(cpuobj, vbi->dev_mem_map[MPCORE_PERIPHBASE].base, "reset-cbar", &error_abort);
        }

        if (vbi->using_psci) {
            RH_DBG("Using PSCI.");
            object_property_set_int(cpuobj, QEMU_PSCI_CONDUIT_HVC, "psci-conduit", &error_abort);
            /* Secondary CPUs start in PSCI powered-down state */
            if (n > 0) {
                object_property_set_bool(cpuobj, true, "start-powered-off", &error_abort);
            }
        }

        object_property_set_link(cpuobj, OBJECT(sysmem), "memory", &error_abort);
        object_property_set_bool(cpuobj, true, "realized", &error_fatal);
    }

    machine->ram_size = vbi->dev_mem_map[MEM].size;
    memory_region_allocate_system_memory(ram, NULL, "ram", machine->ram_size);
    memory_region_add_subregion(sysmem, vbi->dev_mem_map[MEM].base, ram);

    // Memory mapped files (NOTE: file size must be a multiple of 0x1000 for alignment)
    for (int i = 0; i < MAX_MEM_MAPPED_FILES; i++) {
        if (vbi->file_mem_map[i].opt_fn_str != NULL) {
            MemoryRegion *file;
            file = g_malloc0(sizeof(*file));
            assert(file != NULL);
            memory_region_init_ram_from_file(file, NULL, vbi->file_mem_map[i].opt_fn_str,
                vbi->file_mem_map[i].size, false, vbi->file_mem_map[i].opt_fn_str, &error_fatal);
            memory_region_add_subregion(sysmem, vbi->file_mem_map[i].base, file);
            RH_DBG("Mapped %s @ 0x%08lx", vbi->file_mem_map[i].opt_fn_str, vbi->file_mem_map[i].base);
        }
    }

    // Internal GIC
    if (vbi->dev_mem_map[MPCORE_PERIPHBASE].base) {
        RH_DBG("Adding CPU peripheral base @ 0x%08lx", vbi->dev_mem_map[MPCORE_PERIPHBASE].base);
        create_internal_gic(vbi, s, gic_version);
    }

    // Cache controller
    if (vbi->dev_mem_map[CACHE_CTRL].base) {
        // TODO: this is Turris Omnia specific! Will need DTB patching to create a PL310 node on another device
        // PL310 L2 Cache Controller
        RH_DBG("Adding PL310 @ 0x%08lx", vbi->dev_mem_map[CACHE_CTRL].base);
        sysbus_create_varargs("l2x0", vbi->dev_mem_map[CACHE_CTRL].base, NULL);
    }

    // Flash device
    if (vbi->dev_mem_map[FLASH].base) {
        RH_DBG("Adding flash drive device @ 0x%08lx", vbi->dev_mem_map[FLASH].base);
        create_one_flash("virt.flash0", vbi->dev_mem_map[FLASH].base, vbi->dev_mem_map[FLASH].size, NULL, sysmem);
    }


    // TODO: these devices may have already been created in CPU init! Need to check to not overwrite
    // Should create a function that reads sysbus memory map to do this
    // External GIC
    // XXX: nickg: || here because we only learn one device at a time, but still
    // need to initialize what we can so that the controller doesn't think the
    // device failed to initialize.
    if (vbi->dev_mem_map[GIC_DIST].base || vbi->dev_mem_map[GIC_CPU].base) {
        RH_DBG("Adding GICv%i @ 0x%08lx", gic_version, vbi->dev_mem_map[GIC_DIST].base);
        create_external_gic(vbi, s, gic_version, false);
    }

    // VIRTIO devices
    /* Create mmio transports, so the user can create virtio backends
     * (which will be automatically plugged in to the transports). If
     * no backend is created the transport will just sit harmlessly idle. */
    if (vbi->dev_mem_map[VIRT_MMIO].base) {
        RH_DBG("Adding VIRT_MMIO @ 0x%08lx", vbi->dev_mem_map[VIRT_MMIO].base);
        create_virtio_devices(vbi, s->spi);
    }

    //check_sysbus_invariants();

    RH_DBG("KERNEL_CMD: %s", machine->kernel_cmdline);
    RH_DBG("BOARD_ID: %d", machine->board_id);

    vbi->bootinfo.ram_size = machine->ram_size;
    vbi->bootinfo.kernel_filename = machine->kernel_filename;
    vbi->bootinfo.kernel_cmdline = machine->kernel_cmdline;
    vbi->bootinfo.initrd_filename = machine->initrd_filename;
    vbi->bootinfo.nb_cpus = smp_cpus;
    vbi->bootinfo.board_id = machine->board_id;

    vbi->bootinfo.is_linux = true;
    vbi->bootinfo.loader_start = vbi->dev_mem_map[MEM].base;
    vbi->bootinfo.firmware_loaded = firmware_loaded;

    arm_load_kernel(ARM_CPU(first_cpu), &vbi->bootinfo);
}

static void rehosting_machine_class_init(MachineClass *mc)
{
    mc->desc = "Rehosting Machine";
    mc->init = mach_rehosting_init;
    mc->max_cpus = REHOSTING_MAX_CPUS;
    mc->default_ram_size = REHOSTING_DEFAULT_RAM;
    mc->no_cdrom = true;
    mc->no_floppy = true;
    mc->no_parallel = true;
}

DEFINE_MACHINE("rehosting", rehosting_machine_class_init)
