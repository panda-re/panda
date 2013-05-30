/* Copyright (C) 2007-2008 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#include "hw.h"
#include "arm-misc.h"
#include "goldfish_device.h"
#include "irq.h"

enum {
    INTERRUPT_STATUS        = 0x00, // number of pending interrupts
    INTERRUPT_NUMBER        = 0x04,
    INTERRUPT_DISABLE_ALL   = 0x08,
    INTERRUPT_DISABLE       = 0x0c,
    INTERRUPT_ENABLE        = 0x10
};

typedef struct GoldfishInterruptDevice {
    GoldfishDevice dev;
    uint32_t level;
    uint32_t pending_count;
    uint32_t irq_enabled;
    uint32_t fiq_enabled;
    qemu_irq parent_irq;
    qemu_irq parent_fiq;
} GoldfishInterruptDevice;

static void goldfish_int_update(GoldfishInterruptDevice *s)
{
    uint32_t flags;

    flags = (s->level & s->irq_enabled);
    qemu_set_irq(s->parent_irq, flags != 0);

    flags = (s->level & s->fiq_enabled);
    qemu_set_irq(s->parent_fiq, flags != 0);
}

static void goldfish_int_set_irq(void *opaque, int irq, int level)
{
    GoldfishInterruptDevice *s = (GoldfishInterruptDevice *)opaque;
    uint32_t mask = (1U << irq);

    if(level) {
        if(!(s->level & mask)) {
            if(s->irq_enabled & mask)
                s->pending_count++;
            s->level |= mask;
        }
    }
    else {
        if(s->level & mask) {
            if(s->irq_enabled & mask)
                s->pending_count--;
            s->level &= ~mask;
        }
    }
    goldfish_int_update(s);
}

static uint32_t goldfish_int_read(void *opaque, target_phys_addr_t offset)
{
    GoldfishInterruptDevice *s = (GoldfishInterruptDevice *)opaque;

    switch (offset) {
    case INTERRUPT_STATUS: /* IRQ_STATUS */
        return s->pending_count;
    case INTERRUPT_NUMBER: {
        int i;
        uint32_t pending = s->level & s->irq_enabled;
        for(i = 0; i < 32; i++) {
            if(pending & (1U << i))
                return i;
        }
        return 0;
    }
    default:
        cpu_abort (cpu_single_env, "goldfish_int_read: Bad offset %x\n", offset);
        return 0;
    }
}

static void goldfish_int_write(void *opaque, target_phys_addr_t offset, uint32_t value)
{
    GoldfishInterruptDevice *s = (GoldfishInterruptDevice *)opaque;
    uint32_t mask = (1U << value);

    switch (offset) {
        case INTERRUPT_DISABLE_ALL:
            s->pending_count = 0;
            s->level = 0;
            break;

        case INTERRUPT_DISABLE:
            if(s->irq_enabled & mask) {
                if(s->level & mask)
                    s->pending_count--;
                s->irq_enabled &= ~mask;
            }
            break;
        case INTERRUPT_ENABLE:
            if(!(s->irq_enabled & mask)) {
                s->irq_enabled |= mask;
                if(s->level & mask)
                    s->pending_count++;
            }
            break;

    default:
        cpu_abort (cpu_single_env, "goldfish_int_write: Bad offset %x\n", offset);
        return;
    }
    goldfish_int_update(s);
}

static CPUReadMemoryFunc *goldfish_int_readfn[] = {
    goldfish_int_read,
    goldfish_int_read,
    goldfish_int_read
};

static CPUWriteMemoryFunc *goldfish_int_writefn[] = {
    goldfish_int_write,
    goldfish_int_write,
    goldfish_int_write
};

static int goldfish_int_init(GoldfishDevice *dev)
{
    GoldfishInterruptDevice *idev = (GoldfishInterruptDevice *)dev;
    
    qdev_init_gpio_in(&idev->dev.qdev, goldfish_int_set_irq, 32);

    return 0;
}

DeviceState *goldfish_int_create(GoldfishBus *gbus, uint32_t base, qemu_irq parent_irq, qemu_irq parent_fiq)
{
    DeviceState *dev;
    GoldfishDevice *gdev;
    GoldfishInterruptDevice *idev;
    char *name = (char *)"goldfish_int";

    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_prop_set_uint32(dev, "base", base);
    qdev_init_nofail(dev);
    gdev = (GoldfishDevice *)dev;
    idev = DO_UPCAST(GoldfishInterruptDevice, dev, gdev);
    idev->parent_irq = parent_irq;
    idev->parent_fiq = parent_fiq;

    return dev;
}

static const VMStateDescription vmstate_goldfish_int = {
    .name = "goldfish_int",
    .version_id = 1,
    .fields = (VMStateField[]){
        VMSTATE_UINT32(level, GoldfishInterruptDevice),
        VMSTATE_UINT32(pending_count, GoldfishInterruptDevice),
        VMSTATE_UINT32(irq_enabled, GoldfishInterruptDevice),
        VMSTATE_UINT32(fiq_enabled, GoldfishInterruptDevice),
        VMSTATE_END_OF_LIST()
    }
};

static GoldfishDeviceInfo goldfish_int_info = {
    .init = goldfish_int_init,
    .readfn = goldfish_int_readfn,
    .writefn = goldfish_int_writefn,
    .qdev.name  = "goldfish_int",
    .qdev.size  = sizeof(GoldfishInterruptDevice),
    .qdev.vmsd  = &vmstate_goldfish_int,
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, -1),
        DEFINE_PROP_UINT32("base", GoldfishDevice, base, 0),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x1000),
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_int_register(void)
{
    goldfish_bus_register_withprop(&goldfish_int_info);
}
device_init(goldfish_int_register);
