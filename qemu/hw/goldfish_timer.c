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
#include "qemu-common.h"
#include "qemu-timer.h"
#include "cpu.h"
#include "arm-misc.h"
#include "goldfish_device.h"
#include "hw/hw.h"

enum {
    TIMER_TIME_LOW          = 0x00, // get low bits of current time and update TIMER_TIME_HIGH
    TIMER_TIME_HIGH         = 0x04, // get high bits of time at last TIMER_TIME_LOW read
    TIMER_ALARM_LOW         = 0x08, // set low bits of alarm and activate it
    TIMER_ALARM_HIGH        = 0x0c, // set high bits of next alarm
    TIMER_CLEAR_INTERRUPT   = 0x10,
    TIMER_CLEAR_ALARM       = 0x14
};

typedef struct GoldfishTimerDevice {
    GoldfishDevice dev;
    uint32_t alarm_low_ns;
    int32_t alarm_high_ns;
    int64_t now_ns;
    int     armed;
    QEMUTimer *timer;
} GoldfishTimerDevice;

#define  GOLDFISH_TIMER_SAVE_VERSION  1

static void  goldfish_timer_save(QEMUFile*  f, void*  opaque)
{
    struct GoldfishTimerDevice*  s   = opaque;

    qemu_put_be64(f, s->now_ns);  /* in case the kernel is in the middle of a timer read */
    qemu_put_byte(f, s->armed);
    if (s->armed) {
        int64_t  now_ns   = qemu_get_clock_ns(vm_clock);
        int64_t  alarm_ns = (s->alarm_low_ns | (int64_t)s->alarm_high_ns << 32);
        qemu_put_be64(f, alarm_ns - now_ns);
    }
}

static int  goldfish_timer_load(QEMUFile*  f, void*  opaque, int  version_id)
{
    struct GoldfishTimerDevice*  s   = opaque;

    if (version_id != GOLDFISH_TIMER_SAVE_VERSION)
        return -1;

    s->now_ns = qemu_get_be64(f);
    s->armed  = qemu_get_byte(f);
    if (s->armed) {
        int64_t  now_tks   = qemu_get_clock_ns(vm_clock);
        int64_t  diff_tks  = qemu_get_be64(f);
        int64_t  alarm_tks = now_tks + diff_tks;

        if (alarm_tks <= now_tks) {
            goldfish_device_set_irq(&s->dev, 0, 1);
            s->armed = 0;
        } else {
            qemu_mod_timer(s->timer, alarm_tks);
        }
    }
    return 0;
}

static uint32_t goldfish_timer_read(void *opaque, target_phys_addr_t offset)
{
    GoldfishTimerDevice *s = (GoldfishTimerDevice *)opaque;
    switch(offset) {
        case TIMER_TIME_LOW:
            s->now_ns = qemu_get_clock_ns(vm_clock);
            return s->now_ns;
        case TIMER_TIME_HIGH:
            return s->now_ns >> 32;
        default:
            cpu_abort (cpu_single_env, "goldfish_timer_read: Bad offset %x\n", offset);
            return 0;
    }
}

static void goldfish_timer_write(void *opaque, target_phys_addr_t offset, uint32_t value_ns)
{
    GoldfishTimerDevice *s = (GoldfishTimerDevice *)opaque;
    int64_t alarm_ns, now_ns;
    switch(offset) {
        case TIMER_ALARM_LOW:
            s->alarm_low_ns = value_ns;
            alarm_ns = (s->alarm_low_ns | (int64_t)s->alarm_high_ns << 32);
            now_ns   = qemu_get_clock_ns(vm_clock);
            if (alarm_ns <= now_ns) {
                goldfish_device_set_irq(&s->dev, 0, 1);
            } else {
                qemu_mod_timer(s->timer, alarm_ns);
                s->armed = 1;
            }
            break;
        case TIMER_ALARM_HIGH:
            s->alarm_high_ns = value_ns;
            break;
        case TIMER_CLEAR_ALARM:
            qemu_del_timer(s->timer);
            s->armed = 0;
            /* fall through */
        case TIMER_CLEAR_INTERRUPT:
            goldfish_device_set_irq(&s->dev, 0, 0);
            break;
        default:
            cpu_abort (cpu_single_env, "goldfish_timer_write: Bad offset %x\n", offset);
    }
}

static void goldfish_timer_tick(void *opaque)
{
    GoldfishTimerDevice *s = (GoldfishTimerDevice *)opaque;

    s->armed = 0;
    goldfish_device_set_irq(&s->dev, 0, 1);
}

typedef struct GoldfishRTCDevice {
    GoldfishDevice dev;
    uint32_t alarm_low;
    int32_t alarm_high;
    int64_t now;
} GoldfishRTCDevice;

/* we save the RTC for the case where the kernel is in the middle of a rtc_read
 * (i.e. it has read the low 32-bit of s->now, but not the high 32-bits yet */
#define  GOLDFISH_RTC_SAVE_VERSION  1

static void  goldfish_rtc_save(QEMUFile*  f, void*  opaque)
{
    struct GoldfishRTCDevice*  s = opaque;

    qemu_put_be64(f, s->now);
}

static int  goldfish_rtc_load(QEMUFile*  f, void*  opaque, int  version_id)
{
    struct  GoldfishRTCDevice*  s = opaque;

    if (version_id != GOLDFISH_RTC_SAVE_VERSION)
        return -1;

    /* this is an old value that is not correct. but that's ok anyway */
    s->now = qemu_get_be64(f);
    return 0;
}

static uint32_t goldfish_rtc_read(void *opaque, target_phys_addr_t offset)
{
    GoldfishRTCDevice *s = (GoldfishRTCDevice *)opaque;
    switch(offset) {
        case 0x0:
            s->now = (int64_t)time(NULL) * 1000000000;
            return s->now;
        case 0x4:
            return s->now >> 32;
        default:
            cpu_abort (cpu_single_env, "goldfish_rtc_read: Bad offset %x\n", offset);
            return 0;
    }
}

static void goldfish_rtc_write(void *opaque, target_phys_addr_t offset, uint32_t value)
{
    GoldfishRTCDevice *s = (GoldfishRTCDevice *)opaque;
    int64_t alarm;
    switch(offset) {
        case 0x8:
            s->alarm_low = value;
            alarm = s->alarm_low | (int64_t)s->alarm_high << 32;
            //printf("next alarm at %lld, tps %lld\n", alarm, ticks_per_sec);
            //qemu_mod_timer(s->timer, alarm);
            break;
        case 0xc:
            s->alarm_high = value;
            //printf("alarm_high %d\n", s->alarm_high);
            break;
        case 0x10:
            goldfish_device_set_irq(&s->dev, 0, 0);
            break;
        default:
            cpu_abort (cpu_single_env, "goldfish_rtc_write: Bad offset %x\n", offset);
    }
}

static CPUReadMemoryFunc *goldfish_timer_readfn[] = {
    goldfish_timer_read,
    goldfish_timer_read,
    goldfish_timer_read
};

static CPUWriteMemoryFunc *goldfish_timer_writefn[] = {
    goldfish_timer_write,
    goldfish_timer_write,
    goldfish_timer_write
};

static CPUReadMemoryFunc *goldfish_rtc_readfn[] = {
    goldfish_rtc_read,
    goldfish_rtc_read,
    goldfish_rtc_read
};

static CPUWriteMemoryFunc *goldfish_rtc_writefn[] = {
    goldfish_rtc_write,
    goldfish_rtc_write,
    goldfish_rtc_write
};

static int goldfish_timer_init(GoldfishDevice *dev)
{
    GoldfishTimerDevice *tdev = (GoldfishTimerDevice *)dev;
    tdev->timer = qemu_new_timer_ns(vm_clock, goldfish_timer_tick, tdev);
    register_savevm(&dev->qdev, "goldfish_timer", 0, GOLDFISH_TIMER_SAVE_VERSION,
                     goldfish_timer_save, goldfish_timer_load, tdev);
    
    return 0;
}

DeviceState *goldfish_timer_create(GoldfishBus *gbus, uint32_t base, int irq)
{
    DeviceState *dev;
    char *name = (char *)"goldfish_timer";

    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_prop_set_uint32(dev, "base", base);
    qdev_prop_set_uint32(dev, "irq", irq);
    qdev_init_nofail(dev);

    return dev;
}

static GoldfishDeviceInfo goldfish_timer_info = {
    .init = goldfish_timer_init,
    .readfn = goldfish_timer_readfn,
    .writefn = goldfish_timer_writefn,
    .qdev.name  = "goldfish_timer",
    .qdev.size  = sizeof(GoldfishTimerDevice),
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("base", GoldfishDevice, base, 0),
        DEFINE_PROP_UINT32("irq", GoldfishDevice, irq, 0),
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, -1),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x1000),
        DEFINE_PROP_UINT32("irq_count", GoldfishDevice, irq_count, 1),
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_timer_register(void)
{
    goldfish_bus_register_withprop(&goldfish_timer_info);
}
device_init(goldfish_timer_register);

static int goldfish_rtc_init(GoldfishDevice *dev)
{
    register_savevm(&dev->qdev, "goldfish_rtc", 0, GOLDFISH_RTC_SAVE_VERSION,
        goldfish_rtc_save, goldfish_rtc_load, dev);
    return 0;
}

DeviceState *goldfish_rtc_create(GoldfishBus *gbus)
{
    DeviceState *dev;
    char *name = (char *)"goldfish_rtc";

    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_init_nofail(dev);

    return dev;
}

static GoldfishDeviceInfo goldfish_rtc_info = {
    .init = goldfish_rtc_init,
    .readfn = goldfish_rtc_readfn,
    .writefn = goldfish_rtc_writefn,
    .qdev.name  = "goldfish_rtc",
    .qdev.size  = sizeof(GoldfishRTCDevice),
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, -1),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x1000),
        DEFINE_PROP_UINT32("irq_count", GoldfishDevice, irq_count, 1),
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_rtc_register(void)
{
    goldfish_bus_register_withprop(&goldfish_rtc_info);
}
device_init(goldfish_rtc_register);
