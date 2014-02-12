/*
 * QEMU/MIPS pseudo-board
 *
 * emulates a simple machine with ISA-like bus.
 * ISA IO space mapped to the 0x14000000 (PHYS) and
 * ISA memory at the 0x10000000 (PHYS, 16Mb in size).
 * All peripherial devices are attached to this "bus" with
 * the standard PC ISA addresses.
*/
#include "hw.h"
#include "mips.h"
#include "mips_cpudevs.h"
#include "pc.h"
#include "isa.h"
#include "net.h"
#include "sysemu.h"
#include "boards.h"
#include "flash.h"
#include "qemu-log.h"
#include "mips-bios.h"
#include "ide.h"
#include "loader.h"
#include "elf.h"
#include "mc146818rtc.h"
#include "blockdev.h"
#include "exec-memory.h"

#include "sysbus.h"
#include "devices.h"

//static struct arm_boot_info armdummy_binfo;
static QDict *dev_dict;

typedef struct {
    SysBusDevice busdev;
    MemoryRegion iomem;
    QDict *devinfo;
    char *name;
} ARMFlexibleDeviceState;

static uint64_t armdummy_read(void *opaque, target_phys_addr_t addr,
                                    unsigned size)
{
    ARMFlexibleDeviceState *s = opaque;
    // Addr is relative to the base, so we make it absolute
    int64_t base = qdict_get_int(s->devinfo, "base");
    uint64_t real_addr = base+addr;

    QList *addrs = qdict_get_qlist(s->devinfo, "memory");
    QListEntry *entry;
    QTAILQ_FOREACH(entry, &addrs->head, next) {
        QDict *memdict = qobject_to_qdict(entry->value);
        int64_t mem_addr = qdict_get_int(memdict, "address");
        if (mem_addr == real_addr) {
            // TODO: support getting more than one value here
            // For now just return the first entry in the list.
            QList *vals = qdict_get_qlist(memdict, "values");
            return qint_get_int(qobject_to_qint(qlist_peek(vals)));
        }
    }
    
    uint32_t rand_val = (uint32_t) rand();
    rand_val = 0;
    printf("%s (%s): Bad register 0x" TARGET_FMT_plx ", returning %x\n", __func__, s->name, addr, rand_val);
    return rand_val;
}

static void armdummy_write(void *opaque, target_phys_addr_t addr,
                                 uint64_t value, unsigned size)
{
    ARMFlexibleDeviceState *s = opaque;
    printf("%s (%s): Unsupported write to 0x" TARGET_FMT_plx " size %u value %lx\n",
            __func__, s->name, addr, size, value);
}

static const MemoryRegionOps armdummy_ops = {
    .read = armdummy_read,
    .write = armdummy_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static int armdummy_dev_init(SysBusDevice *dev) {
    return 0;
}

static void armdummy_real_dev_init(ARMFlexibleDeviceState *s, char *name, QDict *info) {
    s->name = name;
    s->devinfo = info;

    // Get the size. This is a little silly, but basically loop over
    // the addresses we know about, take the max, and then subtract the
    // base. Add sizeof(target_ulong) for good measure.
    int64_t base = qdict_get_int(info, "base");
    int64_t max_addr = base;
    QList *addrs = qdict_get_qlist(info, "memory");
    QListEntry *entry;
    QTAILQ_FOREACH(entry, &addrs->head, next) {
        QDict *memdict = qobject_to_qdict(entry->value);
        int64_t addr = qdict_get_int(memdict, "address");
        max_addr = MAX(max_addr, addr);
    }

    memory_region_init_io(&s->iomem, &armdummy_ops, s, s->name,
            (max_addr - base)+sizeof(target_ulong));
    sysbus_init_mmio_region(&s->busdev, &s->iomem);
}


#define MAX_IDE_BUS 2
/*
static const int ide_iobase[2] = { 0x1f0, 0x170 };
static const int ide_iobase2[2] = { 0x3f6, 0x376 };
static const int ide_irq[2] = { 14, 15 };
*/
//static ISADevice *pit; /* PIT i8254 */

/* i8254 PIT is attached to the IRQ0 at PIC i8259 */

static struct _loaderparams {
    int ram_size;
    const char *kernel_filename;
    const char *kernel_cmdline;
    const char *initrd_filename;
} loaderparams;

static void mips_qemu_write (void *opaque, target_phys_addr_t addr,
                             uint64_t val, unsigned size)
{
    if ((addr & 0xffff) == 0 && val == 42)
        qemu_system_reset_request ();
    else if ((addr & 0xffff) == 4 && val == 42)
        qemu_system_shutdown_request ();
}

static uint64_t mips_qemu_read (void *opaque, target_phys_addr_t addr,
                                unsigned size)
{
    return 0;
}

static const MemoryRegionOps mips_qemu_ops = {
    .read = mips_qemu_read,
    .write = mips_qemu_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

typedef struct ResetData {
    CPUState *env;
    uint64_t vector;
} ResetData;

static int64_t load_kernel(void)
{
    int64_t entry, kernel_high;
    long kernel_size, initrd_size, params_size;
    ram_addr_t initrd_offset;
    uint32_t *params_buf;
    int big_endian;

#ifdef TARGET_WORDS_BIGENDIAN
    big_endian = 1;
#else
    big_endian = 0;
#endif
    
    // load_image_targphys arg 3 does NOTHING
    load_image_targphys(loaderparams.kernel_filename, 0x1000, ram_size);

    int flash_size = get_image_size(loaderparams.initrd_filename);
    MemoryRegion *flash;
    flash = g_new(MemoryRegion, 1);
    memory_region_init_ram(flash, NULL, "mips_dummy.flash", flash_size);
    memory_region_add_subregion(get_system_memory(), 0x1fc00000, flash);
    load_image_targphys(loaderparams.initrd_filename, 0x1fc00000 , 5);
 
    return 0x80001000;
    

    /* Store command line.  */
    params_size = 264;
    params_buf = g_malloc(params_size);

    params_buf[0] = tswap32(ram_size);
    params_buf[1] = tswap32(0x12345678);

    if (initrd_size > 0) {
        snprintf((char *)params_buf + 8, 256, "rd_start=0x%" PRIx64 " rd_size=%li %s",
                 cpu_mips_phys_to_kseg0(NULL, initrd_offset),
                 initrd_size, loaderparams.kernel_cmdline);
    } else {
        snprintf((char *)params_buf + 8, 256, "%s", loaderparams.kernel_cmdline);
    }

    rom_add_blob_fixed("params", params_buf, params_size,
                       (16 << 20) - 264);

    return entry;
}

static void main_cpu_reset(void *opaque)
{
    ResetData *s = (ResetData *)opaque;
    CPUState *env = s->env;

    cpu_reset(env);
    env->active_tc.PC = s->vector;
    env->active_tc.gpr[29] = 0x803A39C0;
}

static const int sector_len = 32 * 1024;
static
void mips_dummy_init (ram_addr_t ram_siize,
                    const char *boot_device,
                    const char *kernel_filename, const char *kernel_cmdline,
                    const char *initrd_filename, const char *cpu_model)
{
    char *filename;
    MemoryRegion *address_space_mem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    MemoryRegion *bios;
    MemoryRegion *iomem = g_new(MemoryRegion, 1);
    int bios_size;
    CPUState *env;
    ResetData *reset_info;
    int i;
    qemu_irq *i8259;
    DriveInfo *hd[MAX_IDE_BUS * MAX_IDE_DEVS];
    DriveInfo *dinfo;
    int be;

    /* init CPUs */
    if (cpu_model == NULL) {
#ifdef TARGET_MIPS64
        cpu_model = "R4000";
#else
        cpu_model = "24Kf";
#endif
    }
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    reset_info = g_malloc0(sizeof(ResetData));
    reset_info->env = env;
    reset_info->vector = env->active_tc.PC;
    qemu_register_reset(main_cpu_reset, reset_info);

    /* allocate RAM */
    if (ram_size > (256 << 20)) {
        fprintf(stderr,
                "qemu: Too much memory for this machine: %d MB, maximum 256 MB\n",
                ((unsigned int)ram_size / (1 << 20)));
        exit(1);
    }
    memory_region_init_ram(ram, NULL, "mips_r4k.ram", ram_size);

    memory_region_add_subregion(address_space_mem, 0, ram);

    memory_region_init_io(iomem, &mips_qemu_ops, NULL, "mips-qemu", 0x10000);
    memory_region_add_subregion(address_space_mem, 0x1fbf0000, iomem);

#if 0
    /* Try to load a BIOS image. If this fails, we continue regardless,
       but initialize the hardware ourselves. When a kernel gets
       preloaded we also initialize the hardware, since the BIOS wasn't
       run. */
    if (bios_name == NULL)
        bios_name = BIOS_FILENAME;
    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
    if (filename) {
        bios_size = get_image_size(filename);
    } else {
        bios_size = -1;
    }
#ifdef TARGET_WORDS_BIGENDIAN
    be = 1;
#else
    be = 0;
#endif
    if ((bios_size > 0) && (bios_size <= BIOS_SIZE)) {
        bios = g_new(MemoryRegion, 1);
        memory_region_init_ram(bios, NULL, "mips_r4k.bios", BIOS_SIZE);
        memory_region_set_readonly(bios, true);
        memory_region_add_subregion(get_system_memory(), 0x1fc00000, bios);

        load_image_targphys(filename, 0x1fc00000, BIOS_SIZE);
    } else if ((dinfo = drive_get(IF_PFLASH, 0, 0)) != NULL) {
        uint32_t mips_rom = 0x00400000;
        if (!pflash_cfi01_register(0x1fc00000, NULL, "mips_r4k.bios", mips_rom,
                                   dinfo->bdrv, sector_len,
                                   mips_rom / sector_len,
                                   4, 0, 0, 0, 0, be)) {
            fprintf(stderr, "qemu: Error registering flash memory.\n");
	}
    }
    else {
	/* not fatal */
        fprintf(stderr, "qemu: Warning, could not load MIPS bios '%s'\n",
		bios_name);
    }
    if (filename) {
        g_free(filename);
    }
#endif

    const QDictEntry *dev_entry;
    for (dev_entry = qdict_first(dev_dict);
         dev_entry != NULL; dev_entry = qdict_next(dev_dict, dev_entry)) {
        DeviceState *dev = qdev_create(NULL, dev_entry->key);
        qdev_init_nofail(dev);
        QDict *dev_entry_dict = qobject_to_qdict(dev_entry->value);

        int64_t base = qdict_get_int(dev_entry_dict, "base");
        SysBusDevice *sb_dev = sysbus_from_qdev(dev);
        // Init the SysBusDevice state while we have the info in hand
        ARMFlexibleDeviceState *s = FROM_SYSBUS(ARMFlexibleDeviceState, sb_dev);
        // XXX: Stupid.
        armdummy_real_dev_init(s, dev_entry->key, dev_entry_dict);
        // Has to be done here because otherwise nb_mmio == 0
        sysbus_mmio_map(sb_dev, 0, base);
    }

    if (kernel_filename) {
        loaderparams.ram_size = ram_size;
        loaderparams.kernel_filename = kernel_filename;
        loaderparams.kernel_cmdline = kernel_cmdline;
        loaderparams.initrd_filename = initrd_filename;
        reset_info->vector = load_kernel();
    }

    /* Init CPU internal devices */
    cpu_mips_irq_init_cpu(env);
    cpu_mips_clock_init(env);

    /* The PIC is attached to the MIPS CPU INT0 pin */
    //isa_bus_new(NULL, get_system_io());
    //i8259 = i8259_init(env->irq[2]);
    //isa_bus_irqs(i8259);

    //rtc_init(2000, NULL);

    /* Register 64 KB of ISA IO space at 0x14000000 */
    //isa_mmio_init(0x14000000, 0x00010000);
    //isa_mem_base = 0x10000000;

    //pit = pit_init(0x40, 0);

    /*for(i = 0; i < MAX_SERIAL_PORTS; i++) {
        if (serial_hds[i]) {
            serial_isa_init(i, serial_hds[i]);
        }
    }*/

    //isa_vga_init();

    //if (nd_table[0].vlan)
    //    isa_ne2000_init(0x300, 9, &nd_table[0]);

    /*ide_drive_get(hd, MAX_IDE_BUS);
    for(i = 0; i < MAX_IDE_BUS; i++)
        isa_ide_init(ide_iobase[i], ide_iobase2[i], ide_irq[i],
                     hd[MAX_IDE_DEVS * i],
		     hd[MAX_IDE_DEVS * i + 1]);*/

    //isa_create_simple("i8042");
}

static QEMUMachine mips_machine = {
    .name = "mipsdummy",
    .desc = "mips dummy platform",
    .init = mips_dummy_init,
};

static void mips_machine_init(void)
{
    qemu_register_machine(&mips_machine);
}

machine_init(mips_machine_init);

static void armdummy_register_devices(void)
{
    // Read in the JSON file
    FILE *json_file = fopen("device_memory.json", "r");
    size_t json_file_size;
    fseek(json_file, 0, SEEK_END);
    json_file_size = ftell(json_file);
    rewind(json_file);
    char *json_buf = g_new0(char, json_file_size+1);
    assert(fread(json_buf, sizeof(char), json_file_size, json_file) == json_file_size);
    fclose(json_file);

    // Parse
    QObject *dev_js = qobject_from_json(json_buf);
    assert(dev_js != NULL);
    dev_dict = qobject_to_qdict(dev_js); // global
    assert(dev_dict != NULL);

    const QDictEntry *dev_entry;
    for (dev_entry = qdict_first(dev_dict);
         dev_entry != NULL; dev_entry = qdict_next(dev_dict, dev_entry)) {
        // For each device listed:
        // Allocate a SysBusDeviceInfo
        // Allocate a VMStateDescription
        printf("processing device %s\n", dev_entry->key);

        QDict *dev_entry_dict = qobject_to_qdict(dev_entry->value);
        assert(dev_entry_dict != NULL);

        VMStateDescription *dev_vmstate = g_new0(VMStateDescription,1);
        dev_vmstate->name = dev_entry->key;
        dev_vmstate->version_id = 0;
        dev_vmstate->minimum_version_id = 0;
        dev_vmstate->minimum_version_id_old = 0;
        dev_vmstate->fields = g_new0(VMStateField,1); // empty list

        SysBusDeviceInfo *dev_info = g_new0(SysBusDeviceInfo,1);
        dev_info->init       = armdummy_dev_init;
        dev_info->qdev.name  = dev_entry->key;
        dev_info->qdev.desc  = qdict_get_str(dev_entry_dict, "description");
        dev_info->qdev.size  = sizeof(ARMFlexibleDeviceState);
        dev_info->qdev.vmsd  = dev_vmstate;
        dev_info->qdev.props = g_new0(Property,1); // empty list
        sysbus_register_withprop(dev_info);
    }
}


device_init(armdummy_register_devices);
