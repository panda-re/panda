// Initialize PCI devices (on emulators)
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2006 Fabrice Bellard
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "util.h" // dprintf
#include "pci.h" // pci_config_readl
#include "biosvar.h" // GET_EBDA
#include "pci_ids.h" // PCI_VENDOR_ID_INTEL
#include "pci_regs.h" // PCI_COMMAND
#include "xen.h" // usingXen

#define PCI_IO_INDEX_SHIFT 2
#define PCI_MEM_INDEX_SHIFT 12

#define PCI_BRIDGE_IO_MIN      0x1000
#define PCI_BRIDGE_MEM_MIN   0x100000

enum pci_region_type {
    PCI_REGION_TYPE_IO,
    PCI_REGION_TYPE_MEM,
    PCI_REGION_TYPE_PREFMEM,
    PCI_REGION_TYPE_COUNT,
};

static const char *region_type_name[] = {
    [ PCI_REGION_TYPE_IO ]      = "io",
    [ PCI_REGION_TYPE_MEM ]     = "mem",
    [ PCI_REGION_TYPE_PREFMEM ] = "prefmem",
};

static struct pci_bus {
    struct {
        /* pci region stats */
        u32 count[32 - PCI_MEM_INDEX_SHIFT];
        u32 sum, max;
        /* seconday bus region sizes */
        u32 size;
        /* pci region assignments */
        u32 bases[32 - PCI_MEM_INDEX_SHIFT];
        u32 base;
    } r[PCI_REGION_TYPE_COUNT];
} *busses;
static int busses_count;

static void pci_bios_init_device_in_bus(int bus);
static void pci_bios_check_device_in_bus(int bus);
static void pci_bios_init_bus_bases(struct pci_bus *bus);
static void pci_bios_map_device_in_bus(int bus);

static int pci_size_to_index(u32 size, enum pci_region_type type)
{
    int index = __fls(size);
    int shift = (type == PCI_REGION_TYPE_IO) ?
        PCI_IO_INDEX_SHIFT : PCI_MEM_INDEX_SHIFT;

    if (index < shift)
        index = shift;
    index -= shift;
    return index;
}

static u32 pci_index_to_size(int index, enum pci_region_type type)
{
    int shift = (type == PCI_REGION_TYPE_IO) ?
        PCI_IO_INDEX_SHIFT : PCI_MEM_INDEX_SHIFT;

    return 0x1 << (index + shift);
}

static enum pci_region_type pci_addr_to_type(u32 addr)
{
    if (addr & PCI_BASE_ADDRESS_SPACE_IO)
        return PCI_REGION_TYPE_IO;
    if (addr & PCI_BASE_ADDRESS_MEM_PREFETCH)
        return PCI_REGION_TYPE_PREFMEM;
    return PCI_REGION_TYPE_MEM;
}

static u32 pci_size_roundup(u32 size)
{
    int index = __fls(size-1)+1;
    return 0x1 << index;
}

/* host irqs corresponding to PCI irqs A-D */
const u8 pci_irqs[4] = {
    10, 10, 11, 11
};

static u32 pci_bar(u16 bdf, int region_num)
{
    if (region_num != PCI_ROM_SLOT) {
        return PCI_BASE_ADDRESS_0 + region_num * 4;
    }

#define PCI_HEADER_TYPE_MULTI_FUNCTION 0x80
    u8 type = pci_config_readb(bdf, PCI_HEADER_TYPE);
    type &= ~PCI_HEADER_TYPE_MULTI_FUNCTION;
    return type == PCI_HEADER_TYPE_BRIDGE ? PCI_ROM_ADDRESS1 : PCI_ROM_ADDRESS;
}

static void pci_set_io_region_addr(u16 bdf, int region_num, u32 addr)
{
    u32 ofs;

    ofs = pci_bar(bdf, region_num);

    pci_config_writel(bdf, ofs, addr);
}

/* return the global irq number corresponding to a given device irq
   pin. We could also use the bus number to have a more precise
   mapping. */
static int pci_slot_get_pirq(u16 bdf, int irq_num)
{
    int slot_addend = pci_bdf_to_dev(bdf) - 1;
    return (irq_num + slot_addend) & 3;
}

/* PIIX3/PIIX4 PCI to ISA bridge */
static void piix_isa_bridge_init(struct pci_device *pci, void *arg)
{
    int i, irq;
    u8 elcr[2];

    elcr[0] = 0x00;
    elcr[1] = 0x00;
    for (i = 0; i < 4; i++) {
        irq = pci_irqs[i];
        /* set to trigger level */
        elcr[irq >> 3] |= (1 << (irq & 7));
        /* activate irq remapping in PIIX */
        pci_config_writeb(pci->bdf, 0x60 + i, irq);
    }
    outb(elcr[0], 0x4d0);
    outb(elcr[1], 0x4d1);
    dprintf(1, "PIIX3/PIIX4 init: elcr=%02x %02x\n", elcr[0], elcr[1]);
}

static const struct pci_device_id pci_isa_bridge_tbl[] = {
    /* PIIX3/PIIX4 PCI to ISA bridge */
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371SB_0,
               piix_isa_bridge_init),
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371AB_0,
               piix_isa_bridge_init),

    PCI_DEVICE_END
};

#define PCI_IO_ALIGN            4096
#define PCI_IO_SHIFT            8
#define PCI_MEMORY_ALIGN        (1UL << 20)
#define PCI_MEMORY_SHIFT        16
#define PCI_PREF_MEMORY_ALIGN   (1UL << 20)
#define PCI_PREF_MEMORY_SHIFT   16

static void storage_ide_init(struct pci_device *pci, void *arg)
{
    u16 bdf = pci->bdf;
    /* IDE: we map it as in ISA mode */
    pci_set_io_region_addr(bdf, 0, PORT_ATA1_CMD_BASE);
    pci_set_io_region_addr(bdf, 1, PORT_ATA1_CTRL_BASE);
    pci_set_io_region_addr(bdf, 2, PORT_ATA2_CMD_BASE);
    pci_set_io_region_addr(bdf, 3, PORT_ATA2_CTRL_BASE);
}

/* PIIX3/PIIX4 IDE */
static void piix_ide_init(struct pci_device *pci, void *arg)
{
    u16 bdf = pci->bdf;
    pci_config_writew(bdf, 0x40, 0x8000); // enable IDE0
    pci_config_writew(bdf, 0x42, 0x8000); // enable IDE1
}

static void pic_ibm_init(struct pci_device *pci, void *arg)
{
    /* PIC, IBM, MPIC & MPIC2 */
    pci_set_io_region_addr(pci->bdf, 0, 0x80800000 + 0x00040000);
}

static void apple_macio_init(struct pci_device *pci, void *arg)
{
    /* macio bridge */
    pci_set_io_region_addr(pci->bdf, 0, 0x80800000);
}

static const struct pci_device_id pci_class_tbl[] = {
    /* STORAGE IDE */
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371SB_1,
                     PCI_CLASS_STORAGE_IDE, piix_ide_init),
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371AB,
                     PCI_CLASS_STORAGE_IDE, piix_ide_init),
    PCI_DEVICE_CLASS(PCI_ANY_ID, PCI_ANY_ID, PCI_CLASS_STORAGE_IDE,
                     storage_ide_init),

    /* PIC, IBM, MIPC & MPIC2 */
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_IBM, 0x0046, PCI_CLASS_SYSTEM_PIC,
                     pic_ibm_init),
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_IBM, 0xFFFF, PCI_CLASS_SYSTEM_PIC,
                     pic_ibm_init),

    /* 0xff00 */
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_APPLE, 0x0017, 0xff00, apple_macio_init),
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_APPLE, 0x0022, 0xff00, apple_macio_init),

    PCI_DEVICE_END,
};

/* PIIX4 Power Management device (for ACPI) */
static void piix4_pm_init(struct pci_device *pci, void *arg)
{
    u16 bdf = pci->bdf;
    // acpi sci is hardwired to 9
    pci_config_writeb(bdf, PCI_INTERRUPT_LINE, 9);

    pci_config_writel(bdf, 0x40, PORT_ACPI_PM_BASE | 1);
    pci_config_writeb(bdf, 0x80, 0x01); /* enable PM io space */
    pci_config_writel(bdf, 0x90, PORT_SMB_BASE | 1);
    pci_config_writeb(bdf, 0xd2, 0x09); /* enable SMBus io space */
}

static const struct pci_device_id pci_device_tbl[] = {
    /* PIIX4 Power Management device (for ACPI) */
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371AB_3,
               piix4_pm_init),

    PCI_DEVICE_END,
};

static void pci_bios_init_device(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    int pin, pic_irq;

    dprintf(1, "PCI: bus=%d devfn=0x%02x: vendor_id=0x%04x device_id=0x%04x\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_devfn(bdf)
            , pci->vendor, pci->device);
    pci_init_device(pci_class_tbl, pci, NULL);

    /* enable memory mappings */
    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_IO | PCI_COMMAND_MEMORY);

    /* map the interrupt */
    pin = pci_config_readb(bdf, PCI_INTERRUPT_PIN);
    if (pin != 0) {
        pin = pci_slot_get_pirq(bdf, pin - 1);
        pic_irq = pci_irqs[pin];
        pci_config_writeb(bdf, PCI_INTERRUPT_LINE, pic_irq);
    }

    pci_init_device(pci_device_tbl, pci, NULL);
}

static void pci_bios_init_device_in_bus(int bus)
{
    struct pci_device *pci;
    foreachpci(pci) {
        u8 pci_bus = pci_bdf_to_bus(pci->bdf);
        if (pci_bus < bus)
            continue;
        if (pci_bus > bus)
            break;
        pci_bios_init_device(pci);
    }
}

static void
pci_bios_init_bus_rec(int bus, u8 *pci_bus)
{
    int bdf;
    u16 class;

    dprintf(1, "PCI: %s bus = 0x%x\n", __func__, bus);

    /* prevent accidental access to unintended devices */
    foreachbdf(bdf, bus) {
        class = pci_config_readw(bdf, PCI_CLASS_DEVICE);
        if (class == PCI_CLASS_BRIDGE_PCI) {
            pci_config_writeb(bdf, PCI_SECONDARY_BUS, 255);
            pci_config_writeb(bdf, PCI_SUBORDINATE_BUS, 0);
        }
    }

    foreachbdf(bdf, bus) {
        class = pci_config_readw(bdf, PCI_CLASS_DEVICE);
        if (class != PCI_CLASS_BRIDGE_PCI) {
            continue;
        }
        dprintf(1, "PCI: %s bdf = 0x%x\n", __func__, bdf);

        u8 pribus = pci_config_readb(bdf, PCI_PRIMARY_BUS);
        if (pribus != bus) {
            dprintf(1, "PCI: primary bus = 0x%x -> 0x%x\n", pribus, bus);
            pci_config_writeb(bdf, PCI_PRIMARY_BUS, bus);
        } else {
            dprintf(1, "PCI: primary bus = 0x%x\n", pribus);
        }

        u8 secbus = pci_config_readb(bdf, PCI_SECONDARY_BUS);
        (*pci_bus)++;
        if (*pci_bus != secbus) {
            dprintf(1, "PCI: secondary bus = 0x%x -> 0x%x\n",
                    secbus, *pci_bus);
            secbus = *pci_bus;
            pci_config_writeb(bdf, PCI_SECONDARY_BUS, secbus);
        } else {
            dprintf(1, "PCI: secondary bus = 0x%x\n", secbus);
        }

        /* set to max for access to all subordinate buses.
           later set it to accurate value */
        u8 subbus = pci_config_readb(bdf, PCI_SUBORDINATE_BUS);
        pci_config_writeb(bdf, PCI_SUBORDINATE_BUS, 255);

        pci_bios_init_bus_rec(secbus, pci_bus);

        if (subbus != *pci_bus) {
            dprintf(1, "PCI: subordinate bus = 0x%x -> 0x%x\n",
                    subbus, *pci_bus);
            subbus = *pci_bus;
        } else {
            dprintf(1, "PCI: subordinate bus = 0x%x\n", subbus);
        }
        pci_config_writeb(bdf, PCI_SUBORDINATE_BUS, subbus);
    }
}

static void
pci_bios_init_bus(void)
{
    u8 pci_bus = 0;
    pci_bios_init_bus_rec(0 /* host bus */, &pci_bus);
    busses_count = pci_bus + 1;
}

static void pci_bios_bus_get_bar(struct pci_bus *bus, int bdf, int bar,
                                 u32 *val, u32 *size)
{
    u32 ofs = pci_bar(bdf, bar);
    u32 old = pci_config_readl(bdf, ofs);
    u32 mask;

    if (bar == PCI_ROM_SLOT) {
        mask = PCI_ROM_ADDRESS_MASK;
        pci_config_writel(bdf, ofs, mask);
    } else {
        if (old & PCI_BASE_ADDRESS_SPACE_IO)
            mask = PCI_BASE_ADDRESS_IO_MASK;
        else
            mask = PCI_BASE_ADDRESS_MEM_MASK;
        pci_config_writel(bdf, ofs, ~0);
    }
    *val = pci_config_readl(bdf, ofs);
    pci_config_writel(bdf, ofs, old);
    *size = (~(*val & mask)) + 1;
}

static void pci_bios_bus_reserve(struct pci_bus *bus, int type, u32 size)
{
    u32 index;

    index = pci_size_to_index(size, type);
    size = pci_index_to_size(index, type);
    bus->r[type].count[index]++;
    bus->r[type].sum += size;
    if (bus->r[type].max < size)
        bus->r[type].max = size;
}

static u32 pci_bios_bus_get_addr(struct pci_bus *bus, int type, u32 size)
{
    u32 index, addr;

    index = pci_size_to_index(size, type);
    addr = bus->r[type].bases[index];
    bus->r[type].bases[index] += pci_index_to_size(index, type);
    return addr;
}

static void pci_bios_check_device(struct pci_bus *bus, struct pci_device *dev)
{
    u16 bdf = dev->bdf;
    u32 limit;
    int i,type;

    if (dev->class == PCI_CLASS_BRIDGE_PCI) {
        if (dev->secondary_bus >= busses_count) {
            /* should never trigger */
            dprintf(1, "PCI: bus count too small (%d), skipping bus #%d\n",
                    busses_count, dev->secondary_bus);
            return;
        }
        struct pci_bus *s = busses + dev->secondary_bus;
        pci_bios_check_device_in_bus(dev->secondary_bus);
        for (type = 0; type < PCI_REGION_TYPE_COUNT; type++) {
            limit = (type == PCI_REGION_TYPE_IO) ?
                PCI_BRIDGE_IO_MIN : PCI_BRIDGE_MEM_MIN;
            s->r[type].size = s->r[type].sum;
            if (s->r[type].size < limit)
                s->r[type].size = limit;
            s->r[type].size = pci_size_roundup(s->r[type].size);
            pci_bios_bus_reserve(bus, type, s->r[type].size);
        }
        dprintf(1, "PCI: secondary bus %d sizes: io %x, mem %x, prefmem %x\n",
                dev->secondary_bus,
                s->r[PCI_REGION_TYPE_IO].size,
                s->r[PCI_REGION_TYPE_MEM].size,
                s->r[PCI_REGION_TYPE_PREFMEM].size);
        return;
    }

    for (i = 0; i < PCI_NUM_REGIONS; i++) {
        u32 val, size;
        pci_bios_bus_get_bar(bus, bdf, i, &val, &size);
        if (val == 0) {
            continue;
        }
        pci_bios_bus_reserve(bus, pci_addr_to_type(val), size);
        dev->bars[i].addr = val;
        dev->bars[i].size = size;
        dev->bars[i].is64 = (!(val & PCI_BASE_ADDRESS_SPACE_IO) &&
            (val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64);

        if (dev->bars[i].is64) {
            i++;
        }
    }
}

static void pci_bios_map_device(struct pci_bus *bus, struct pci_device *dev)
{
    u16 bdf = dev->bdf;
    int type, i;

    if (dev->class == PCI_CLASS_BRIDGE_PCI) {
        if (dev->secondary_bus >= busses_count) {
            return;
        }
        struct pci_bus *s = busses + dev->secondary_bus;
        u32 base, limit;

        for (type = 0; type < PCI_REGION_TYPE_COUNT; type++) {
            s->r[type].base = pci_bios_bus_get_addr(bus, type, s->r[type].size);
        }
        dprintf(1, "PCI: init bases bus %d (secondary)\n", dev->secondary_bus);
        pci_bios_init_bus_bases(s);

        base = s->r[PCI_REGION_TYPE_IO].base;
        limit = base + s->r[PCI_REGION_TYPE_IO].size - 1;
        pci_config_writeb(bdf, PCI_IO_BASE, base >> PCI_IO_SHIFT);
        pci_config_writew(bdf, PCI_IO_BASE_UPPER16, 0);
        pci_config_writeb(bdf, PCI_IO_LIMIT, limit >> PCI_IO_SHIFT);
        pci_config_writew(bdf, PCI_IO_LIMIT_UPPER16, 0);

        base = s->r[PCI_REGION_TYPE_MEM].base;
        limit = base + s->r[PCI_REGION_TYPE_MEM].size - 1;
        pci_config_writew(bdf, PCI_MEMORY_BASE, base >> PCI_MEMORY_SHIFT);
        pci_config_writew(bdf, PCI_MEMORY_LIMIT, limit >> PCI_MEMORY_SHIFT);

        base = s->r[PCI_REGION_TYPE_PREFMEM].base;
        limit = base + s->r[PCI_REGION_TYPE_PREFMEM].size - 1;
        pci_config_writew(bdf, PCI_PREF_MEMORY_BASE, base >> PCI_PREF_MEMORY_SHIFT);
        pci_config_writew(bdf, PCI_PREF_MEMORY_LIMIT, limit >> PCI_PREF_MEMORY_SHIFT);
        pci_config_writel(bdf, PCI_PREF_BASE_UPPER32, 0);
        pci_config_writel(bdf, PCI_PREF_LIMIT_UPPER32, 0);

        pci_bios_map_device_in_bus(dev->secondary_bus);
        return;
    }

    for (i = 0; i < PCI_NUM_REGIONS; i++) {
        u32 addr;
        if (dev->bars[i].addr == 0) {
            continue;
        }

        addr = pci_bios_bus_get_addr(bus, pci_addr_to_type(dev->bars[i].addr),
                                     dev->bars[i].size);
        dprintf(1, "  bar %d, addr %x, size %x [%s]\n",
                i, addr, dev->bars[i].size,
                dev->bars[i].addr & PCI_BASE_ADDRESS_SPACE_IO ? "io" : "mem");
        pci_set_io_region_addr(bdf, i, addr);

        if (dev->bars[i].is64) {
            i++;
        }
    }
}

static void pci_bios_check_device_in_bus(int bus)
{
    struct pci_device *pci;

    dprintf(1, "PCI: check devices bus %d\n", bus);
    foreachpci(pci) {
        if (pci_bdf_to_bus(pci->bdf) != bus)
            continue;
        pci_bios_check_device(&busses[bus], pci);
    }
}

static void pci_bios_map_device_in_bus(int bus)
{
    struct pci_device *pci;

    foreachpci(pci) {
        if (pci_bdf_to_bus(pci->bdf) != bus)
            continue;
        dprintf(1, "PCI: map device bus %d, bfd 0x%x\n", bus, pci->bdf);
        pci_bios_map_device(&busses[bus], pci);
    }
}

static void pci_bios_init_bus_bases(struct pci_bus *bus)
{
    u32 base, newbase, size;
    int type, i;

    for (type = 0; type < PCI_REGION_TYPE_COUNT; type++) {
        dprintf(1, "  type %s max %x sum %x base %x\n", region_type_name[type],
                bus->r[type].max, bus->r[type].sum, bus->r[type].base);
        base = bus->r[type].base;
        for (i = ARRAY_SIZE(bus->r[type].count)-1; i >= 0; i--) {
            size = pci_index_to_size(i, type);
            if (!bus->r[type].count[i])
                continue;
            newbase = base + size * bus->r[type].count[i];
            dprintf(1, "    size %8x: %d bar(s), %8x -> %8x\n",
                    size, bus->r[type].count[i], base, newbase - 1);
            bus->r[type].bases[i] = base;
            base = newbase;
        }
    }
}

#define ROOT_BASE(top, sum, align) ALIGN_DOWN((top)-(sum),(align))

static int pci_bios_init_root_regions(u32 start, u32 end)
{
    struct pci_bus *bus = &busses[0];

    bus->r[PCI_REGION_TYPE_IO].base = 0xc000;

    if (bus->r[PCI_REGION_TYPE_MEM].sum < bus->r[PCI_REGION_TYPE_PREFMEM].sum) {
        bus->r[PCI_REGION_TYPE_MEM].base =
            ROOT_BASE(end,
                      bus->r[PCI_REGION_TYPE_MEM].sum,
                      bus->r[PCI_REGION_TYPE_MEM].max);
        bus->r[PCI_REGION_TYPE_PREFMEM].base =
            ROOT_BASE(bus->r[PCI_REGION_TYPE_MEM].base,
                      bus->r[PCI_REGION_TYPE_PREFMEM].sum,
                      bus->r[PCI_REGION_TYPE_PREFMEM].max);
        if (bus->r[PCI_REGION_TYPE_PREFMEM].base >= start) {
            return 0;
        }
    } else {
        bus->r[PCI_REGION_TYPE_PREFMEM].base =
            ROOT_BASE(end,
                      bus->r[PCI_REGION_TYPE_PREFMEM].sum,
                      bus->r[PCI_REGION_TYPE_PREFMEM].max);
        bus->r[PCI_REGION_TYPE_MEM].base =
            ROOT_BASE(bus->r[PCI_REGION_TYPE_PREFMEM].base,
                      bus->r[PCI_REGION_TYPE_MEM].sum,
                      bus->r[PCI_REGION_TYPE_MEM].max);
        if (bus->r[PCI_REGION_TYPE_MEM].base >= start) {
            return 0;
        }
    }
    return -1;
}

void
pci_setup(void)
{
    if (CONFIG_COREBOOT || usingXen()) {
        // PCI setup already done by coreboot or Xen - just do probe.
        pci_probe();
        return;
    }

    dprintf(3, "pci setup\n");

    u32 start = BUILD_PCIMEM_START;
    u32 end   = BUILD_PCIMEM_END;

    dprintf(1, "=== PCI bus & bridge init ===\n");
    pci_bios_init_bus();

    dprintf(1, "=== PCI device probing ===\n");
    pci_probe();

    dprintf(1, "=== PCI new allocation pass #1 ===\n");
    busses = malloc_tmp(sizeof(*busses) * busses_count);
    memset(busses, 0, sizeof(*busses) * busses_count);
    pci_bios_check_device_in_bus(0 /* host bus */);
    if (pci_bios_init_root_regions(start, end) != 0) {
        panic("PCI: out of address space\n");
    }

    dprintf(1, "=== PCI new allocation pass #2 ===\n");
    dprintf(1, "PCI: init bases bus 0 (primary)\n");
    pci_bios_init_bus_bases(&busses[0]);
    pci_bios_map_device_in_bus(0 /* host bus */);

    pci_bios_init_device_in_bus(0 /* host bus */);

    struct pci_device *pci;
    foreachpci(pci) {
        pci_init_device(pci_isa_bridge_tbl, pci, NULL);
    }

    free(busses);
    busses_count = 0;
}
