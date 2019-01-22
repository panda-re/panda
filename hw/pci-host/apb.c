/*
 * QEMU Ultrasparc APB PCI host
 *
 * Copyright (c) 2006 Fabrice Bellard
 * Copyright (c) 2012,2013 Artyom Tarasenko
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* XXX This file and most of its contents are somewhat misnamed.  The
   Ultrasparc PCI host is called the PCI Bus Module (PBM).  The APB is
   the secondary PCI bridge.  */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci-host/apb.h"
#include "sysemu/sysemu.h"
#include "exec/address-spaces.h"
#include "qemu/log.h"

/* debug APB */
//#define DEBUG_APB

#ifdef DEBUG_APB
#define APB_DPRINTF(fmt, ...) \
do { printf("APB: " fmt , ## __VA_ARGS__); } while (0)
#else
#define APB_DPRINTF(fmt, ...)
#endif

/* debug IOMMU */
//#define DEBUG_IOMMU

#ifdef DEBUG_IOMMU
#define IOMMU_DPRINTF(fmt, ...) \
do { printf("IOMMU: " fmt , ## __VA_ARGS__); } while (0)
#else
#define IOMMU_DPRINTF(fmt, ...)
#endif

/*
 * Chipset docs:
 * PBM: "UltraSPARC IIi User's Manual",
 * http://www.sun.com/processors/manuals/805-0087.pdf
 *
 * APB: "Advanced PCI Bridge (APB) User's Manual",
 * http://www.sun.com/processors/manuals/805-1251.pdf
 */

#define PBM_PCI_IMR_MASK    0x7fffffff
#define PBM_PCI_IMR_ENABLED 0x80000000

#define POR          (1U << 31)
#define SOFT_POR     (1U << 30)
#define SOFT_XIR     (1U << 29)
#define BTN_POR      (1U << 28)
#define BTN_XIR      (1U << 27)
#define RESET_MASK   0xf8000000
#define RESET_WCMASK 0x98000000
#define RESET_WMASK  0x60000000

#define MAX_IVEC 0x40
#define NO_IRQ_REQUEST (MAX_IVEC + 1)

#define IOMMU_PAGE_SIZE_8K      (1ULL << 13)
#define IOMMU_PAGE_MASK_8K      (~(IOMMU_PAGE_SIZE_8K - 1))
#define IOMMU_PAGE_SIZE_64K     (1ULL << 16)
#define IOMMU_PAGE_MASK_64K     (~(IOMMU_PAGE_SIZE_64K - 1))

#define IOMMU_NREGS             3

#define IOMMU_CTRL              0x0
#define IOMMU_CTRL_TBW_SIZE     (1ULL << 2)
#define IOMMU_CTRL_MMU_EN       (1ULL)

#define IOMMU_CTRL_TSB_SHIFT    16

#define IOMMU_BASE              0x8
#define IOMMU_FLUSH             0x10

#define IOMMU_TTE_DATA_V        (1ULL << 63)
#define IOMMU_TTE_DATA_SIZE     (1ULL << 61)
#define IOMMU_TTE_DATA_W        (1ULL << 1)

#define IOMMU_TTE_PHYS_MASK_8K  0x1ffffffe000ULL
#define IOMMU_TTE_PHYS_MASK_64K 0x1ffffff8000ULL

#define IOMMU_TSB_8K_OFFSET_MASK_8M    0x00000000007fe000ULL
#define IOMMU_TSB_8K_OFFSET_MASK_16M   0x0000000000ffe000ULL
#define IOMMU_TSB_8K_OFFSET_MASK_32M   0x0000000001ffe000ULL
#define IOMMU_TSB_8K_OFFSET_MASK_64M   0x0000000003ffe000ULL
#define IOMMU_TSB_8K_OFFSET_MASK_128M  0x0000000007ffe000ULL
#define IOMMU_TSB_8K_OFFSET_MASK_256M  0x000000000fffe000ULL
#define IOMMU_TSB_8K_OFFSET_MASK_512M  0x000000001fffe000ULL
#define IOMMU_TSB_8K_OFFSET_MASK_1G    0x000000003fffe000ULL

#define IOMMU_TSB_64K_OFFSET_MASK_64M  0x0000000003ff0000ULL
#define IOMMU_TSB_64K_OFFSET_MASK_128M 0x0000000007ff0000ULL
#define IOMMU_TSB_64K_OFFSET_MASK_256M 0x000000000fff0000ULL
#define IOMMU_TSB_64K_OFFSET_MASK_512M 0x000000001fff0000ULL
#define IOMMU_TSB_64K_OFFSET_MASK_1G   0x000000003fff0000ULL
#define IOMMU_TSB_64K_OFFSET_MASK_2G   0x000000007fff0000ULL

typedef struct IOMMUState {
    AddressSpace iommu_as;
    MemoryRegion iommu;

    uint64_t regs[IOMMU_NREGS];
} IOMMUState;

#define TYPE_APB "pbm"

#define APB_DEVICE(obj) \
    OBJECT_CHECK(APBState, (obj), TYPE_APB)

typedef struct APBState {
    PCIHostState parent_obj;

    MemoryRegion apb_config;
    MemoryRegion pci_config;
    MemoryRegion pci_mmio;
    MemoryRegion pci_ioport;
    uint64_t pci_irq_in;
    IOMMUState iommu;
    uint32_t pci_control[16];
    uint32_t pci_irq_map[8];
    uint32_t pci_err_irq_map[4];
    uint32_t obio_irq_map[32];
    qemu_irq *pbm_irqs;
    qemu_irq *ivec_irqs;
    unsigned int irq_request;
    uint32_t reset_control;
    unsigned int nr_resets;
} APBState;

static inline void pbm_set_request(APBState *s, unsigned int irq_num)
{
    APB_DPRINTF("%s: request irq %d\n", __func__, irq_num);

    s->irq_request = irq_num;
    qemu_set_irq(s->ivec_irqs[irq_num], 1);
}

static inline void pbm_check_irqs(APBState *s)
{

    unsigned int i;

    /* Previous request is not acknowledged, resubmit */
    if (s->irq_request != NO_IRQ_REQUEST) {
        pbm_set_request(s, s->irq_request);
        return;
    }
    /* no request pending */
    if (s->pci_irq_in == 0ULL) {
        return;
    }
    for (i = 0; i < 32; i++) {
        if (s->pci_irq_in & (1ULL << i)) {
            if (s->pci_irq_map[i >> 2] & PBM_PCI_IMR_ENABLED) {
                pbm_set_request(s, i);
                return;
            }
        }
    }
    for (i = 32; i < 64; i++) {
        if (s->pci_irq_in & (1ULL << i)) {
            if (s->obio_irq_map[i - 32] & PBM_PCI_IMR_ENABLED) {
                pbm_set_request(s, i);
                break;
            }
        }
    }
}

static inline void pbm_clear_request(APBState *s, unsigned int irq_num)
{
    APB_DPRINTF("%s: clear request irq %d\n", __func__, irq_num);
    qemu_set_irq(s->ivec_irqs[irq_num], 0);
    s->irq_request = NO_IRQ_REQUEST;
}

static AddressSpace *pbm_pci_dma_iommu(PCIBus *bus, void *opaque, int devfn)
{
    IOMMUState *is = opaque;

    return &is->iommu_as;
}

/* Called from RCU critical section */
static IOMMUTLBEntry pbm_translate_iommu(MemoryRegion *iommu, hwaddr addr,
                                         bool is_write)
{
    IOMMUState *is = container_of(iommu, IOMMUState, iommu);
    hwaddr baseaddr, offset;
    uint64_t tte;
    uint32_t tsbsize;
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = 0,
        .translated_addr = 0,
        .addr_mask = ~(hwaddr)0,
        .perm = IOMMU_NONE,
    };

    if (!(is->regs[IOMMU_CTRL >> 3] & IOMMU_CTRL_MMU_EN)) {
        /* IOMMU disabled, passthrough using standard 8K page */
        ret.iova = addr & IOMMU_PAGE_MASK_8K;
        ret.translated_addr = addr;
        ret.addr_mask = IOMMU_PAGE_MASK_8K;
        ret.perm = IOMMU_RW;

        return ret;
    }

    baseaddr = is->regs[IOMMU_BASE >> 3];
    tsbsize = (is->regs[IOMMU_CTRL >> 3] >> IOMMU_CTRL_TSB_SHIFT) & 0x7;

    if (is->regs[IOMMU_CTRL >> 3] & IOMMU_CTRL_TBW_SIZE) {
        /* 64K */
        switch (tsbsize) {
        case 0:
            offset = (addr & IOMMU_TSB_64K_OFFSET_MASK_64M) >> 13;
            break;
        case 1:
            offset = (addr & IOMMU_TSB_64K_OFFSET_MASK_128M) >> 13;
            break;
        case 2:
            offset = (addr & IOMMU_TSB_64K_OFFSET_MASK_256M) >> 13;
            break;
        case 3:
            offset = (addr & IOMMU_TSB_64K_OFFSET_MASK_512M) >> 13;
            break;
        case 4:
            offset = (addr & IOMMU_TSB_64K_OFFSET_MASK_1G) >> 13;
            break;
        case 5:
            offset = (addr & IOMMU_TSB_64K_OFFSET_MASK_2G) >> 13;
            break;
        default:
            /* Not implemented, error */
            return ret;
        }
    } else {
        /* 8K */
        switch (tsbsize) {
        case 0:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_8M) >> 10;
            break;
        case 1:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_16M) >> 10;
            break;
        case 2:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_32M) >> 10;
            break;
        case 3:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_64M) >> 10;
            break;
        case 4:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_128M) >> 10;
            break;
        case 5:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_256M) >> 10;
            break;
        case 6:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_512M) >> 10;
            break;
        case 7:
            offset = (addr & IOMMU_TSB_8K_OFFSET_MASK_1G) >> 10;
            break;
        }
    }

    tte = address_space_ldq_be(&address_space_memory, baseaddr + offset,
                               MEMTXATTRS_UNSPECIFIED, NULL);

    if (!(tte & IOMMU_TTE_DATA_V)) {
        /* Invalid mapping */
        return ret;
    }

    if (tte & IOMMU_TTE_DATA_W) {
        /* Writeable */
        ret.perm = IOMMU_RW;
    } else {
        ret.perm = IOMMU_RO;
    }

    /* Extract phys */
    if (tte & IOMMU_TTE_DATA_SIZE) {
        /* 64K */
        ret.iova = addr & IOMMU_PAGE_MASK_64K;
        ret.translated_addr = tte & IOMMU_TTE_PHYS_MASK_64K;
        ret.addr_mask = (IOMMU_PAGE_SIZE_64K - 1);
    } else {
        /* 8K */
        ret.iova = addr & IOMMU_PAGE_MASK_8K;
        ret.translated_addr = tte & IOMMU_TTE_PHYS_MASK_8K;
        ret.addr_mask = (IOMMU_PAGE_SIZE_8K - 1);
    }

    return ret;
}

static MemoryRegionIOMMUOps pbm_iommu_ops = {
    .translate = pbm_translate_iommu,
};

static void iommu_config_write(void *opaque, hwaddr addr,
                               uint64_t val, unsigned size)
{
    IOMMUState *is = opaque;

    IOMMU_DPRINTF("IOMMU config write: 0x%" HWADDR_PRIx " val: %" PRIx64
                  " size: %d\n", addr, val, size);

    switch (addr) {
    case IOMMU_CTRL:
        if (size == 4) {
            is->regs[IOMMU_CTRL >> 3] &= 0xffffffffULL;
            is->regs[IOMMU_CTRL >> 3] |= val << 32;
        } else {
            is->regs[IOMMU_CTRL >> 3] = val;
        }
        break;
    case IOMMU_CTRL + 0x4:
        is->regs[IOMMU_CTRL >> 3] &= 0xffffffff00000000ULL;
        is->regs[IOMMU_CTRL >> 3] |= val & 0xffffffffULL;
        break;
    case IOMMU_BASE:
        if (size == 4) {
            is->regs[IOMMU_BASE >> 3] &= 0xffffffffULL;
            is->regs[IOMMU_BASE >> 3] |= val << 32;
        } else {
            is->regs[IOMMU_BASE >> 3] = val;
        }
        break;
    case IOMMU_BASE + 0x4:
        is->regs[IOMMU_BASE >> 3] &= 0xffffffff00000000ULL;
        is->regs[IOMMU_BASE >> 3] |= val & 0xffffffffULL;
        break;
    case IOMMU_FLUSH:
    case IOMMU_FLUSH + 0x4:
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                  "apb iommu: Unimplemented register write "
                  "reg 0x%" HWADDR_PRIx " size 0x%x value 0x%" PRIx64 "\n",
                  addr, size, val);
        break;
    }
}

static uint64_t iommu_config_read(void *opaque, hwaddr addr, unsigned size)
{
    IOMMUState *is = opaque;
    uint64_t val;

    switch (addr) {
    case IOMMU_CTRL:
        if (size == 4) {
            val = is->regs[IOMMU_CTRL >> 3] >> 32;
        } else {
            val = is->regs[IOMMU_CTRL >> 3];
        }
        break;
    case IOMMU_CTRL + 0x4:
        val = is->regs[IOMMU_CTRL >> 3] & 0xffffffffULL;
        break;
    case IOMMU_BASE:
        if (size == 4) {
            val = is->regs[IOMMU_BASE >> 3] >> 32;
        } else {
            val = is->regs[IOMMU_BASE >> 3];
        }
        break;
    case IOMMU_BASE + 0x4:
        val = is->regs[IOMMU_BASE >> 3] & 0xffffffffULL;
        break;
    case IOMMU_FLUSH:
    case IOMMU_FLUSH + 0x4:
        val = 0;
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "apb iommu: Unimplemented register read "
                      "reg 0x%" HWADDR_PRIx " size 0x%x\n",
                      addr, size);
        val = 0;
        break;
    }

    IOMMU_DPRINTF("IOMMU config read: 0x%" HWADDR_PRIx " val: %" PRIx64
                  " size: %d\n", addr, val, size);

    return val;
}

static void apb_config_writel (void *opaque, hwaddr addr,
                               uint64_t val, unsigned size)
{
    APBState *s = opaque;
    IOMMUState *is = &s->iommu;

    APB_DPRINTF("%s: addr " TARGET_FMT_plx " val %" PRIx64 "\n", __func__, addr, val);

    switch (addr & 0xffff) {
    case 0x30 ... 0x4f: /* DMA error registers */
        /* XXX: not implemented yet */
        break;
    case 0x200 ... 0x217: /* IOMMU */
        iommu_config_write(is, (addr & 0x1f), val, size);
        break;
    case 0xc00 ... 0xc3f: /* PCI interrupt control */
        if (addr & 4) {
            unsigned int ino = (addr & 0x3f) >> 3;
            s->pci_irq_map[ino] &= PBM_PCI_IMR_MASK;
            s->pci_irq_map[ino] |= val & ~PBM_PCI_IMR_MASK;
            if ((s->irq_request == ino) && !(val & ~PBM_PCI_IMR_MASK)) {
                pbm_clear_request(s, ino);
            }
            pbm_check_irqs(s);
        }
        break;
    case 0x1000 ... 0x107f: /* OBIO interrupt control */
        if (addr & 4) {
            unsigned int ino = ((addr & 0xff) >> 3);
            s->obio_irq_map[ino] &= PBM_PCI_IMR_MASK;
            s->obio_irq_map[ino] |= val & ~PBM_PCI_IMR_MASK;
            if ((s->irq_request == (ino | 0x20))
                 && !(val & ~PBM_PCI_IMR_MASK)) {
                pbm_clear_request(s, ino | 0x20);
            }
            pbm_check_irqs(s);
        }
        break;
    case 0x1400 ... 0x14ff: /* PCI interrupt clear */
        if (addr & 4) {
            unsigned int ino = (addr & 0xff) >> 5;
            if ((s->irq_request / 4)  == ino) {
                pbm_clear_request(s, s->irq_request);
                pbm_check_irqs(s);
            }
        }
        break;
    case 0x1800 ... 0x1860: /* OBIO interrupt clear */
        if (addr & 4) {
            unsigned int ino = ((addr & 0xff) >> 3) | 0x20;
            if (s->irq_request == ino) {
                pbm_clear_request(s, ino);
                pbm_check_irqs(s);
            }
        }
        break;
    case 0x2000 ... 0x202f: /* PCI control */
        s->pci_control[(addr & 0x3f) >> 2] = val;
        break;
    case 0xf020 ... 0xf027: /* Reset control */
        if (addr & 4) {
            val &= RESET_MASK;
            s->reset_control &= ~(val & RESET_WCMASK);
            s->reset_control |= val & RESET_WMASK;
            if (val & SOFT_POR) {
                s->nr_resets = 0;
                qemu_system_reset_request();
            } else if (val & SOFT_XIR) {
                qemu_system_reset_request();
            }
        }
        break;
    case 0x5000 ... 0x51cf: /* PIO/DMA diagnostics */
    case 0xa400 ... 0xa67f: /* IOMMU diagnostics */
    case 0xa800 ... 0xa80f: /* Interrupt diagnostics */
    case 0xf000 ... 0xf01f: /* FFB config, memory control */
        /* we don't care */
    default:
        break;
    }
}

static uint64_t apb_config_readl (void *opaque,
                                  hwaddr addr, unsigned size)
{
    APBState *s = opaque;
    IOMMUState *is = &s->iommu;
    uint32_t val;

    switch (addr & 0xffff) {
    case 0x30 ... 0x4f: /* DMA error registers */
        val = 0;
        /* XXX: not implemented yet */
        break;
    case 0x200 ... 0x217: /* IOMMU */
        val = iommu_config_read(is, (addr & 0x1f), size);
        break;
    case 0xc00 ... 0xc3f: /* PCI interrupt control */
        if (addr & 4) {
            val = s->pci_irq_map[(addr & 0x3f) >> 3];
        } else {
            val = 0;
        }
        break;
    case 0x1000 ... 0x107f: /* OBIO interrupt control */
        if (addr & 4) {
            val = s->obio_irq_map[(addr & 0xff) >> 3];
        } else {
            val = 0;
        }
        break;
    case 0x1080 ... 0x108f: /* PCI bus error */
        if (addr & 4) {
            val = s->pci_err_irq_map[(addr & 0xf) >> 3];
        } else {
            val = 0;
        }
        break;
    case 0x2000 ... 0x202f: /* PCI control */
        val = s->pci_control[(addr & 0x3f) >> 2];
        break;
    case 0xf020 ... 0xf027: /* Reset control */
        if (addr & 4) {
            val = s->reset_control;
        } else {
            val = 0;
        }
        break;
    case 0x5000 ... 0x51cf: /* PIO/DMA diagnostics */
    case 0xa400 ... 0xa67f: /* IOMMU diagnostics */
    case 0xa800 ... 0xa80f: /* Interrupt diagnostics */
    case 0xf000 ... 0xf01f: /* FFB config, memory control */
        /* we don't care */
    default:
        val = 0;
        break;
    }
    APB_DPRINTF("%s: addr " TARGET_FMT_plx " -> %x\n", __func__, addr, val);

    return val;
}

static const MemoryRegionOps apb_config_ops = {
    .read = apb_config_readl,
    .write = apb_config_writel,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void apb_pci_config_write(void *opaque, hwaddr addr,
                                 uint64_t val, unsigned size)
{
    APBState *s = opaque;
    PCIHostState *phb = PCI_HOST_BRIDGE(s);

    val = qemu_bswap_len(val, size);
    APB_DPRINTF("%s: addr " TARGET_FMT_plx " val %" PRIx64 "\n", __func__, addr, val);
    pci_data_write(phb->bus, addr, val, size);
}

static uint64_t apb_pci_config_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    uint32_t ret;
    APBState *s = opaque;
    PCIHostState *phb = PCI_HOST_BRIDGE(s);

    ret = pci_data_read(phb->bus, addr, size);
    ret = qemu_bswap_len(ret, size);
    APB_DPRINTF("%s: addr " TARGET_FMT_plx " -> %x\n", __func__, addr, ret);
    return ret;
}

/* The APB host has an IRQ line for each IRQ line of each slot.  */
static int pci_apb_map_irq(PCIDevice *pci_dev, int irq_num)
{
    return ((pci_dev->devfn & 0x18) >> 1) + irq_num;
}

static int pci_pbm_map_irq(PCIDevice *pci_dev, int irq_num)
{
    int bus_offset;
    if (pci_dev->devfn & 1)
        bus_offset = 16;
    else
        bus_offset = 0;
    return (bus_offset + (PCI_SLOT(pci_dev->devfn) << 2) + irq_num) & 0x1f;
}

static void pci_apb_set_irq(void *opaque, int irq_num, int level)
{
    APBState *s = opaque;

    APB_DPRINTF("%s: set irq_in %d level %d\n", __func__, irq_num, level);
    /* PCI IRQ map onto the first 32 INO.  */
    if (irq_num < 32) {
        if (level) {
            s->pci_irq_in |= 1ULL << irq_num;
            if (s->pci_irq_map[irq_num >> 2] & PBM_PCI_IMR_ENABLED) {
                pbm_set_request(s, irq_num);
            }
        } else {
            s->pci_irq_in &= ~(1ULL << irq_num);
        }
    } else {
        /* OBIO IRQ map onto the next 32 INO.  */
        if (level) {
            APB_DPRINTF("%s: set irq %d level %d\n", __func__, irq_num, level);
            s->pci_irq_in |= 1ULL << irq_num;
            if ((s->irq_request == NO_IRQ_REQUEST)
                && (s->obio_irq_map[irq_num - 32] & PBM_PCI_IMR_ENABLED)) {
                pbm_set_request(s, irq_num);
            }
        } else {
            s->pci_irq_in &= ~(1ULL << irq_num);
        }
    }
}

static void apb_pci_bridge_realize(PCIDevice *dev, Error **errp)
{
    pci_bridge_initfn(dev, TYPE_PCI_BUS);

    /*
     * command register:
     * According to PCI bridge spec, after reset
     *   bus master bit is off
     *   memory space enable bit is off
     * According to manual (805-1251.pdf).
     *   the reset value should be zero unless the boot pin is tied high
     *   (which is true) and thus it should be PCI_COMMAND_MEMORY.
     */
    pci_set_word(dev->config + PCI_COMMAND,
                 PCI_COMMAND_MEMORY);
    pci_set_word(dev->config + PCI_STATUS,
                 PCI_STATUS_FAST_BACK | PCI_STATUS_66MHZ |
                 PCI_STATUS_DEVSEL_MEDIUM);
}

PCIBus *pci_apb_init(hwaddr special_base,
                     hwaddr mem_base,
                     qemu_irq *ivec_irqs, PCIBus **bus2, PCIBus **bus3,
                     qemu_irq **pbm_irqs)
{
    DeviceState *dev;
    SysBusDevice *s;
    PCIHostState *phb;
    APBState *d;
    IOMMUState *is;
    PCIDevice *pci_dev;
    PCIBridge *br;

    /* Ultrasparc PBM main bus */
    dev = qdev_create(NULL, TYPE_APB);
    d = APB_DEVICE(dev);
    phb = PCI_HOST_BRIDGE(dev);
    phb->bus = pci_register_bus(DEVICE(phb), "pci",
                                pci_apb_set_irq, pci_pbm_map_irq, d,
                                &d->pci_mmio,
                                get_system_io(),
                                0, 32, TYPE_PCI_BUS);
    qdev_init_nofail(dev);
    s = SYS_BUS_DEVICE(dev);
    /* apb_config */
    sysbus_mmio_map(s, 0, special_base);
    /* PCI configuration space */
    sysbus_mmio_map(s, 1, special_base + 0x1000000ULL);
    /* pci_ioport */
    sysbus_mmio_map(s, 2, special_base + 0x2000000ULL);

    memory_region_init(&d->pci_mmio, OBJECT(s), "pci-mmio", 0x100000000ULL);
    memory_region_add_subregion(get_system_memory(), mem_base, &d->pci_mmio);

    *pbm_irqs = d->pbm_irqs;
    d->ivec_irqs = ivec_irqs;

    pci_create_simple(phb->bus, 0, "pbm-pci");

    /* APB IOMMU */
    is = &d->iommu;
    memset(is, 0, sizeof(IOMMUState));

    memory_region_init_iommu(&is->iommu, OBJECT(dev), &pbm_iommu_ops,
                             "iommu-apb", UINT64_MAX);
    address_space_init(&is->iommu_as, &is->iommu, "pbm-as");
    pci_setup_iommu(phb->bus, pbm_pci_dma_iommu, is);

    /* APB secondary busses */
    pci_dev = pci_create_multifunction(phb->bus, PCI_DEVFN(1, 0), true,
                                   "pbm-bridge");
    br = PCI_BRIDGE(pci_dev);
    pci_bridge_map_irq(br, "Advanced PCI Bus secondary bridge 1",
                       pci_apb_map_irq);
    qdev_init_nofail(&pci_dev->qdev);
    *bus2 = pci_bridge_get_sec_bus(br);

    pci_dev = pci_create_multifunction(phb->bus, PCI_DEVFN(1, 1), true,
                                   "pbm-bridge");
    br = PCI_BRIDGE(pci_dev);
    pci_bridge_map_irq(br, "Advanced PCI Bus secondary bridge 2",
                       pci_apb_map_irq);
    qdev_init_nofail(&pci_dev->qdev);
    *bus3 = pci_bridge_get_sec_bus(br);

    return phb->bus;
}

static void pci_pbm_reset(DeviceState *d)
{
    unsigned int i;
    APBState *s = APB_DEVICE(d);

    for (i = 0; i < 8; i++) {
        s->pci_irq_map[i] &= PBM_PCI_IMR_MASK;
    }
    for (i = 0; i < 32; i++) {
        s->obio_irq_map[i] &= PBM_PCI_IMR_MASK;
    }

    s->irq_request = NO_IRQ_REQUEST;
    s->pci_irq_in = 0ULL;

    if (s->nr_resets++ == 0) {
        /* Power on reset */
        s->reset_control = POR;
    }
}

static const MemoryRegionOps pci_config_ops = {
    .read = apb_pci_config_read,
    .write = apb_pci_config_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static int pci_pbm_init_device(SysBusDevice *dev)
{
    APBState *s;
    unsigned int i;

    s = APB_DEVICE(dev);
    for (i = 0; i < 8; i++) {
        s->pci_irq_map[i] = (0x1f << 6) | (i << 2);
    }
    for (i = 0; i < 2; i++) {
        s->pci_err_irq_map[i] = (0x1f << 6) | 0x30;
    }
    for (i = 0; i < 32; i++) {
        s->obio_irq_map[i] = ((0x1f << 6) | 0x20) + i;
    }
    s->pbm_irqs = qemu_allocate_irqs(pci_apb_set_irq, s, MAX_IVEC);
    s->irq_request = NO_IRQ_REQUEST;
    s->pci_irq_in = 0ULL;

    /* apb_config */
    memory_region_init_io(&s->apb_config, OBJECT(s), &apb_config_ops, s,
                          "apb-config", 0x10000);
    /* at region 0 */
    sysbus_init_mmio(dev, &s->apb_config);

    memory_region_init_io(&s->pci_config, OBJECT(s), &pci_config_ops, s,
                          "apb-pci-config", 0x1000000);
    /* at region 1 */
    sysbus_init_mmio(dev, &s->pci_config);

    /* pci_ioport */
    memory_region_init_alias(&s->pci_ioport, OBJECT(s), "apb-pci-ioport",
                             get_system_io(), 0, 0x10000);
    /* at region 2 */
    sysbus_init_mmio(dev, &s->pci_ioport);

    return 0;
}

static void pbm_pci_host_realize(PCIDevice *d, Error **errp)
{
    pci_set_word(d->config + PCI_COMMAND,
                 PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
    pci_set_word(d->config + PCI_STATUS,
                 PCI_STATUS_FAST_BACK | PCI_STATUS_66MHZ |
                 PCI_STATUS_DEVSEL_MEDIUM);
}

static void pbm_pci_host_class_init(ObjectClass *klass, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->realize = pbm_pci_host_realize;
    k->vendor_id = PCI_VENDOR_ID_SUN;
    k->device_id = PCI_DEVICE_ID_SUN_SABRE;
    k->class_id = PCI_CLASS_BRIDGE_HOST;
    /*
     * PCI-facing part of the host bridge, not usable without the
     * host-facing part, which can't be device_add'ed, yet.
     */
    dc->user_creatable = false;
}

static const TypeInfo pbm_pci_host_info = {
    .name          = "pbm-pci",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIDevice),
    .class_init    = pbm_pci_host_class_init,
};

static void pbm_host_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = pci_pbm_init_device;
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    dc->reset = pci_pbm_reset;
}

static const TypeInfo pbm_host_info = {
    .name          = TYPE_APB,
    .parent        = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(APBState),
    .class_init    = pbm_host_class_init,
};

static void pbm_pci_bridge_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = apb_pci_bridge_realize;
    k->exit = pci_bridge_exitfn;
    k->vendor_id = PCI_VENDOR_ID_SUN;
    k->device_id = PCI_DEVICE_ID_SUN_SIMBA;
    k->revision = 0x11;
    k->config_write = pci_bridge_write_config;
    k->is_bridge = 1;
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    dc->reset = pci_bridge_reset;
    dc->vmsd = &vmstate_pci_device;
}

static const TypeInfo pbm_pci_bridge_info = {
    .name          = "pbm-bridge",
    .parent        = TYPE_PCI_BRIDGE,
    .class_init    = pbm_pci_bridge_class_init,
};

static void pbm_register_types(void)
{
    type_register_static(&pbm_host_info);
    type_register_static(&pbm_pci_host_info);
    type_register_static(&pbm_pci_bridge_info);
}

type_init(pbm_register_types)
