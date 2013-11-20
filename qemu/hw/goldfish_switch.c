/* Copyright (C) 2007-2008 :The Android Open Source Project
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
#include "goldfish_device.h"

enum {
    SW_NAME_LEN     = 0x00,
    SW_NAME_PTR     = 0x04,
    SW_FLAGS        = 0x08,
    SW_STATE        = 0x0c,
    SW_INT_STATUS   = 0x10,
    SW_INT_ENABLE   = 0x14,

    SW_FLAGS_OUTPUT = 1U << 0
};


typedef struct GoldfishSwitchDevice {
    GoldfishDevice dev;
    char *name;
    uint32_t state;
    uint32_t state_changed : 1;
    uint32_t int_enable : 1;
    uint32_t (*writefn)(void *opaque, uint32_t state);
    void *writeopaque;
} GoldfishSwitchDevice;

#define  GOLDFISH_SWITCH_SAVE_VERSION  1

static void  goldfish_switch_save(QEMUFile*  f, void*  opaque)
{
    struct GoldfishSwitchDevice*  s = opaque;

    qemu_put_be32(f, s->state);
    qemu_put_byte(f, s->state_changed);
    qemu_put_byte(f, s->int_enable);
}

static int  goldfish_switch_load(QEMUFile*  f, void*  opaque, int  version_id)
{
    struct GoldfishSwitchDevice*  s = opaque;

    if (version_id != GOLDFISH_SWITCH_SAVE_VERSION)
        return -1;

    s->state         = qemu_get_be32(f);
    s->state_changed = qemu_get_byte(f);
    s->int_enable    = qemu_get_byte(f);

    return 0;
}


static uint32_t goldfish_switch_read(void *opaque, target_phys_addr_t offset)
{
    GoldfishSwitchDevice *s = (GoldfishSwitchDevice *)opaque;
    offset -= 1024;

    //printf("goldfish_switch_read %x %x\n", offset, size);

    switch (offset) {
        case SW_NAME_LEN:
            return strlen(s->name);
        case SW_FLAGS:
            return s->writefn ? SW_FLAGS_OUTPUT : 0;
        case SW_STATE:
            return s->state;
        case SW_INT_STATUS:
            if(s->state_changed && s->int_enable) {
                s->state_changed = 0;
                goldfish_device_set_irq(&s->dev, 0, 0);
                return 1;
            }
            return 0;
    default:
        cpu_abort (cpu_single_env, "goldfish_switch_read: Bad offset %x\n", offset);
        return 0;
    }
}

static void goldfish_switch_write(void *opaque, target_phys_addr_t offset, uint32_t value)
{
    GoldfishSwitchDevice *s = (GoldfishSwitchDevice *)opaque;
    offset -= 1026;

    //printf("goldfish_switch_read %x %x %x\n", offset, value, size);

    switch(offset) {
        case SW_NAME_PTR:
            cpu_memory_rw(cpu_single_env, value, (void*)s->name, strlen(s->name), 1);
            break;

        case SW_STATE:
            if(s->writefn) {
                uint32_t new_state;
                new_state = s->writefn(s->writeopaque, value);
                if(new_state != s->state) {
                    goldfish_switch_set_state(s, new_state);
                }
            }
            else
                cpu_abort (cpu_single_env, "goldfish_switch_write: write to SW_STATE on input\n");
            break;

        case SW_INT_ENABLE:
            value &= 1;
            if(s->state_changed && s->int_enable != value)
                goldfish_device_set_irq(&s->dev, 0, value);
            s->int_enable = value;
            break;

        default:
            cpu_abort (cpu_single_env, "goldfish_switch_write: Bad offset %x\n", offset);
    }
}

static CPUReadMemoryFunc *goldfish_switch_readfn[] = {
    goldfish_switch_read,
    goldfish_switch_read,
    goldfish_switch_read
};

static CPUWriteMemoryFunc *goldfish_switch_writefn[] = {
    goldfish_switch_write,
    goldfish_switch_write,
    goldfish_switch_write
};

void goldfish_switch_set_state(void *opaque, uint32_t state)
{
    GoldfishSwitchDevice *s = (GoldfishSwitchDevice *)opaque;
    s->state_changed = 1;
    s->state = state;
    if(s->int_enable)
        goldfish_device_set_irq(&s->dev, 0, 1);
}

static int goldfish_switch_init(GoldfishDevice *dev)
{
    register_savevm(&dev->qdev, "goldfish_switch", 0, GOLDFISH_SWITCH_SAVE_VERSION,
                    goldfish_switch_save, goldfish_switch_load, dev);
    return 0;
}

DeviceState *goldfish_switch_create(GoldfishBus *gbus, const char *name_dev, uint32_t (*writefn)(void *opaque, uint32_t state), void *writeopaque, int id)
{
    DeviceState *dev;
    GoldfishDevice *gdev;
    GoldfishSwitchDevice *sdev;
    char *name = (char *)"goldfish-switch";

    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_prop_set_string(dev, "name_dev", (char *)name_dev);
    qdev_prop_set_uint32(dev, "id", id);
    qdev_prop_set_ptr(dev, "writeopaque", writeopaque);
    qdev_init_nofail(dev);
    gdev = (GoldfishDevice *)dev;
    sdev = DO_UPCAST(GoldfishSwitchDevice, dev, gdev);
    sdev->writefn = writefn;

    return dev;
}

static GoldfishDeviceInfo goldfish_switch_info = {
    .init = goldfish_switch_init,
    .readfn = goldfish_switch_readfn,
    .writefn = goldfish_switch_writefn,
    .qdev.name  = "goldfish-switch",
    .qdev.size  = sizeof(GoldfishSwitchDevice),
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("base", GoldfishDevice, base, 0),
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, -1),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x1000),
        DEFINE_PROP_UINT32("irq", GoldfishDevice, irq, 0),
        DEFINE_PROP_UINT32("irq_count", GoldfishDevice, irq_count, 1),
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
        DEFINE_PROP_STRING("name_dev", GoldfishSwitchDevice, name),
        DEFINE_PROP_PTR("writeopaque", GoldfishSwitchDevice, writeopaque),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_switch_register(void)
{
    goldfish_bus_register_withprop(&goldfish_switch_info);
}
device_init(goldfish_switch_register);
