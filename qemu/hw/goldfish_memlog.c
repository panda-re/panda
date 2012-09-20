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
#include "goldfish_device.h"


typedef struct GoldfishMemlogDevice {
    GoldfishDevice dev;
    int fd;
} GoldfishMemlogDevice;

static uint32_t memlog_read(void *opaque, target_phys_addr_t offset)
{
    (void)opaque;
    (void)offset;
    return 0;
}

static void memlog_write(void *opaque, target_phys_addr_t offset, uint32_t val)
{
    static unsigned info[8];
    char buf[128];
    GoldfishMemlogDevice *s = (GoldfishMemlogDevice *)opaque;
    int ret;

    (void)s->dev;

    if (offset < 8*4)
        info[offset / 4] = val;

    if (offset == 0) {
            /* write PID and VADDR to logfile */
        snprintf(buf, sizeof buf, "%08x %08x\n", info[0], info[1]);
        do {
            ret = write(s->fd, buf, strlen(buf));
        } while (ret < 0 && errno == EINTR);
    }
}


static CPUReadMemoryFunc *memlog_readfn[] = {
   memlog_read,
   memlog_read,
   memlog_read
};

static CPUWriteMemoryFunc *memlog_writefn[] = {
   memlog_write,
   memlog_write,
   memlog_write
};

static int goldfish_memlog_init(GoldfishDevice *dev)
{
    GoldfishMemlogDevice *s = (GoldfishMemlogDevice *)dev;
    do {
        s->fd = open("mem.log", /* O_CREAT | */ O_TRUNC | O_WRONLY, 0644);
    } while (s->fd < 0 && errno == EINTR);

    return 0;
}

DeviceState *goldfish_memlog_create(GoldfishBus *gbus, uint32_t base)
{
    DeviceState *dev;
    char *name = (char *)"goldfish_memlog";

    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_prop_set_uint32(dev, "base", base);
    qdev_init_nofail(dev);

    return dev;
}

static GoldfishDeviceInfo goldfish_memlog_info = {
    .init = goldfish_memlog_init,
    .readfn = memlog_readfn,
    .writefn = memlog_writefn,
    .qdev.name  = "goldfish_memlog",
    .qdev.size  = sizeof(GoldfishMemlogDevice),
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("base", GoldfishDevice, base, 0),
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, 0),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x1000),
        DEFINE_PROP_UINT32("irq", GoldfishDevice, irq, 0),
        DEFINE_PROP_UINT32("irq_count", GoldfishDevice, irq_count, 0),
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
        DEFINE_PROP_INT32("fd", GoldfishMemlogDevice, fd, -1),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_memlog_register(void)
{
    goldfish_bus_register_withprop(&goldfish_memlog_info);
}
device_init(goldfish_memlog_register);
