/*
 * ARM generic (JSON device config) emulation.
 *
 * This code is licensed under the GPL.
 */

#include "sysbus.h"
#include "arm-misc.h"
#include "primecell.h"
#include "devices.h"
#include "net.h"
#include "sysemu.h"
#include "pci.h"
#include "usb-ohci.h"
#include "boards.h"
#include "blockdev.h"

// For parsing the device memory map
#include "qstring.h"
#include "qint.h"
#include "qdict.h"
#include "qlist.h"
#include "qfloat.h"
#include "qbool.h"
#include "qjson.h"

static struct arm_boot_info armdummy_binfo;
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

static void armdummy_init(ram_addr_t ram_size,
                     const char *boot_device,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename, const char *cpu_model)
{
    // Eventually we will want to read this from a config file
    int board_id = 0x1337;
    target_phys_addr_t load_addr = 0x50000;
    CPUState *env;
    ram_addr_t ram_offset = 0;
    if (!cpu_model)
        cpu_model = "arm1176";
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    ram_offset = qemu_ram_alloc(NULL, "armdummy.ram", ram_size);
    cpu_register_physical_memory(0, ram_size, ram_offset | IO_MEM_RAM);

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

    armdummy_binfo.ram_size = ram_size;
    armdummy_binfo.kernel_filename = kernel_filename;
    armdummy_binfo.kernel_load_address = load_addr;
    armdummy_binfo.kernel_cmdline = kernel_cmdline;
    armdummy_binfo.initrd_filename = initrd_filename;
    armdummy_binfo.board_id = board_id;
    arm_load_kernel(env, &armdummy_binfo);
}

static QEMUMachine armdummy_machine = {
    .name = "armdummy",
    .desc = "dummy ARM board",
    .init = armdummy_init,
};

static void armdummy_machine_init(void)
{
    qemu_register_machine(&armdummy_machine);
}

machine_init(armdummy_machine_init);

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

device_init(armdummy_register_devices)
