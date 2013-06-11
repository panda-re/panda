/*
 * ARM Versatile Platform/Application Baseboard System emulation.
 *
 * Copyright (c) 2005-2007 CodeSourcery.
 * Written by Paul Brook
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

static struct arm_boot_info armdummy_binfo;

typedef struct {
    SysBusDevice busdev;
    MemoryRegion iomem;
    CharDriverState *chr;
} ARMDummyUARTState;

typedef struct {
    SysBusDevice busdev;
    MemoryRegion iomem;
} ARMDummyBootArgsState;

typedef struct {
    SysBusDevice busdev;
    MemoryRegion iomem;
} ARMDummyBoardInfoState;

#define BOOTARGS_BASE   0x0b050000
#define BOARDINFO_BASE  0xbd030100
#define UART_BASE       0xbd370400
#define UART2_BASE      0xbd3e0c00
#define UART_DR 0x14
#define UART_CR 0x04

static uint64_t armdummy_boardinfo_read(void *opaque, target_phys_addr_t addr,
                                    unsigned size)
{
    switch (addr) {
    case 0x100:
        return 0x00002600;
    default:
        printf("%s: Bad register 0x" TARGET_FMT_plx "\n", __func__, addr);
        return 0;
    }
}

static void armdummy_boardinfo_write(void *opaque, target_phys_addr_t addr,
                                 uint64_t value, unsigned size)
{
    printf("%s: Unsupported write to 0x" TARGET_FMT_plx " size %u value %lx\n", __func__, addr, size, value);
}

static const MemoryRegionOps armdummy_boardinfo_ops = {
    .read = armdummy_boardinfo_read,
    .write = armdummy_boardinfo_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static uint64_t armdummy_uart_read(void *opaque, target_phys_addr_t addr,
                                    unsigned size)
{
    //ARMDummyUARTState *s = opaque;
    switch (addr) {
    case UART_CR:
        // We only know of one value here, which should be 0x4
        return 0x4;
    case UART_DR:
        // XXX Unimplemented
        return 0;
    default:
        printf("%s: Bad register 0x" TARGET_FMT_plx "\n", __func__, addr);
        return 0;
    }
}

static void armdummy_uart_write(void *opaque, target_phys_addr_t addr,
                                 uint64_t value, unsigned size)
{
    ARMDummyUARTState *s = opaque;
    uint8_t val = 0;

    switch (addr) {
    case UART_DR:
        if (s->chr) {
            val = value & 0xFF;
            qemu_chr_fe_write(s->chr, &val, 1);
        }
        break;
    default:
        printf("%s: Bad register 0x" TARGET_FMT_plx "\n", __func__, addr);
    }
}

static const MemoryRegionOps armdummy_uart_ops = {
    .read = armdummy_uart_read,
    .write = armdummy_uart_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static int armdummy_uart_can_receive(void *opaque) {
    // XXX Unimplemented
    return 1;
}

static void armdummy_uart_receive(void *opaque, const uint8_t *buf, int size) {
    // XXX Unimplemented
    return;
}

static void armdummy_uart_event(void *opaque, int event)
{
    // XXX Unimplemented
    return;
}


static int armdummy_uart_init(SysBusDevice *dev)
{
    ARMDummyUARTState *s = FROM_SYSBUS(ARMDummyUARTState, dev);

    memory_region_init_io(&s->iomem, &armdummy_uart_ops, s, "uart", 0x18);
    sysbus_init_mmio_region(dev, &s->iomem);

    if (s->chr) {
        qemu_chr_add_handlers(s->chr,
                        armdummy_uart_can_receive,
                        armdummy_uart_receive,
                        armdummy_uart_event,
                        s);
    }

    return 0;
}

static uint64_t armdummy_bootargs_read(void *opaque, target_phys_addr_t addr,
                                    unsigned size)
{
    switch (addr) {
        case 0x0:
            // "UEFI"
            return 0x55454649;
        case 0x4:
        case 0x8:
            return 0x3;
        case 0x90:
            // Device ID. One of:
            // 0x201 <Khanplete> 
            // 0x202 <Jackal>
            // 0x203 <Mercury>
            // 0x204 <TanzanitePlus> 
            // 0x205 <Sapphire>
            // 0x206 <MonoKhanplete> 
            // 0x207 <JAZ>
            // 0x208 <Annapurna> 
            // 0x209 <Frosty>
            // 0x20a <Rudolph>
            // 0x20b <Denali>
            // 0x20c <Everest>
            // 0x20d <TwoKhan>
            // 0x20e <Tahiti>
            // 0x20f <Fiji>
            // 0x210 <Camas>
            // 0x211 <Azalea>
            // 0x212 <Redwood>
            // 0x213 <Cypress>

            // Our board is <Jackal>
            return 0x00000202;
        case 0xa0:
            // Memory size
            return 0x40cbe000;
        case 0xa4:
            // ACPI location
            return 0x3fd5e000;
        case 0xb0:
            // Only constraint known: != 0
            return 1;
        case 0xbc:
            // Memory start
            return 0x12d88000+0x2D000000;
        default:
        {
            uint64_t val = 0;
            printf("%s: Bad register 0x" TARGET_FMT_plx ", returning %lx\n", __func__, addr, val);
            return val;
        }
    }
}

static void armdummy_bootargs_write(void *opaque, target_phys_addr_t addr,
                                 uint64_t value, unsigned size)
{
    printf("%s: Unsupported write to 0x" TARGET_FMT_plx " size %u value %lx\n", __func__, addr, size, value);
}

static const MemoryRegionOps armdummy_bootargs_ops = {
    .read = armdummy_bootargs_read,
    .write = armdummy_bootargs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static int armdummy_bootargs_init(SysBusDevice *dev) {
    ARMDummyBootArgsState *s = FROM_SYSBUS(ARMDummyBootArgsState, dev);

    memory_region_init_io(&s->iomem, &armdummy_bootargs_ops, s, "bootargs", 0xd0);
    sysbus_init_mmio_region(dev, &s->iomem);

    return 0;
}

static int armdummy_boardinfo_init(SysBusDevice *dev) {
    ARMDummyBoardInfoState *s = FROM_SYSBUS(ARMDummyBoardInfoState, dev);

    memory_region_init_io(&s->iomem, &armdummy_boardinfo_ops, s, "boardinfo", 0x4);
    sysbus_init_mmio_region(dev, &s->iomem);

    return 0;
}

static const VMStateDescription vmstate_armdummy_uart_regs = {
    .name = "armdummy-uart",
    .version_id = 0,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .fields = (VMStateField[]) {
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription vmstate_armdummy_bootargs = {
    .name = "armdummy-bootargs",
    .version_id = 0,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .fields = (VMStateField[]) {
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription vmstate_armdummy_boardinfo = {
    .name = "armdummy-boardinfo",
    .version_id = 0,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .fields = (VMStateField[]) {
        VMSTATE_END_OF_LIST(),
    },
};

static SysBusDeviceInfo armdummy_boardinfo_info = {
    .init       = armdummy_boardinfo_init,
    .qdev.name  = "armdummy-boardinfo",
    .qdev.desc  = "Dummy ARM BoardInfo device",
    .qdev.size  = sizeof(ARMDummyBoardInfoState),
    .qdev.vmsd  = &vmstate_armdummy_boardinfo,
    .qdev.props = (Property[]) {
        DEFINE_PROP_END_OF_LIST(),
    }
};

static SysBusDeviceInfo armdummy_bootargs_info = {
    .init       = armdummy_bootargs_init,
    .qdev.name  = "armdummy-bootargs",
    .qdev.desc  = "Dummy ARM BootArgs device",
    .qdev.size  = sizeof(ARMDummyBootArgsState),
    .qdev.vmsd  = &vmstate_armdummy_bootargs,
    .qdev.props = (Property[]) {
        DEFINE_PROP_END_OF_LIST(),
    }
};

static SysBusDeviceInfo armdummy_uart_info = {
    .init       = armdummy_uart_init,
    .qdev.name  = "armdummy-uart",
    .qdev.desc  = "Dummy ARM UART controller",
    .qdev.size  = sizeof(ARMDummyUARTState),
    .qdev.vmsd  = &vmstate_armdummy_uart_regs,
    .qdev.props = (Property[]) {
        DEFINE_PROP_CHR("chardev", ARMDummyUARTState, chr),
        DEFINE_PROP_END_OF_LIST(),
    }
};


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

    // Serial port (debug interface)
    DeviceState *dev = qdev_create(NULL, "armdummy-uart");
    qdev_prop_set_chr(dev, "chardev", serial_hds[0]);
    qdev_init_nofail(dev);
    sysbus_mmio_map(sysbus_from_qdev(dev), 0, UART_BASE);

    dev = qdev_create(NULL, "armdummy-uart");
    qdev_prop_set_chr(dev, "chardev", serial_hds[1]);
    qdev_init_nofail(dev);
    sysbus_mmio_map(sysbus_from_qdev(dev), 0, UART2_BASE);

    // Unknown device that holds "bootargs"
    dev = qdev_create(NULL, "armdummy-bootargs");
    qdev_init_nofail(dev);
    sysbus_mmio_map(sysbus_from_qdev(dev), 0, BOOTARGS_BASE);

    // Unknown device that holds just the board info (so far)
    dev = qdev_create(NULL, "armdummy-boardinfo");
    qdev_init_nofail(dev);
    sysbus_mmio_map(sysbus_from_qdev(dev), 0, BOARDINFO_BASE);

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
    sysbus_register_withprop(&armdummy_uart_info);
    sysbus_register_withprop(&armdummy_bootargs_info);
    sysbus_register_withprop(&armdummy_boardinfo_info);
}

device_init(armdummy_register_devices)
