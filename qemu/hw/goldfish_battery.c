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
#include "power_supply.h"


enum {
	/* status register */
	BATTERY_INT_STATUS	    = 0x00,
	/* set this to enable IRQ */
	BATTERY_INT_ENABLE	    = 0x04,

	BATTERY_AC_ONLINE       = 0x08,
	BATTERY_STATUS          = 0x0C,
	BATTERY_HEALTH          = 0x10,
	BATTERY_PRESENT         = 0x14,
	BATTERY_CAPACITY        = 0x18,

	BATTERY_STATUS_CHANGED	= 1U << 0,
	AC_STATUS_CHANGED   	= 1U << 1,
	BATTERY_INT_MASK        = BATTERY_STATUS_CHANGED | AC_STATUS_CHANGED,
};


typedef struct GoldfishBatteryDevice {
    GoldfishDevice dev;
    // IRQs
    uint32_t int_status;
    // irq enable mask for int_status
    uint32_t int_enable;

    int ac_online;
    int status;
    int health;
    int present;
    int capacity;
} GoldfishBatteryDevice;

static uint32_t goldfish_battery_read(void *opaque, target_phys_addr_t offset)
{
    uint32_t ret;
    GoldfishBatteryDevice *s = (GoldfishBatteryDevice *)opaque;

    switch(offset) {
        case BATTERY_INT_STATUS:
            // return current buffer status flags
            ret = s->int_status & s->int_enable;
            if (ret) {
                goldfish_device_set_irq(&s->dev, 0, 0);
                s->int_status = 0;
            }
            return ret;

		case BATTERY_INT_ENABLE:
		    return s->int_enable;
		case BATTERY_AC_ONLINE:
		    return s->ac_online;
		case BATTERY_STATUS:
		    return s->status;
		case BATTERY_HEALTH:
		    return s->health;
		case BATTERY_PRESENT:
		    return s->present;
		case BATTERY_CAPACITY:
		    return s->capacity;

        default:
            cpu_abort (cpu_single_env, "goldfish_battery_read: Bad offset %x\n", offset);
            return 0;
    }
}

static void goldfish_battery_write(void *opaque, target_phys_addr_t offset, uint32_t val)
{
    GoldfishBatteryDevice *s = (GoldfishBatteryDevice *)opaque;

    switch(offset) {
        case BATTERY_INT_ENABLE:
            /* enable interrupts */
            s->int_enable = val;
//            s->int_status = (AUDIO_INT_WRITE_BUFFER_1_EMPTY | AUDIO_INT_WRITE_BUFFER_2_EMPTY);
//            goldfish_device_set_irq(&s->dev, 0, (s->int_status & s->int_enable));
            break;

        default:
            cpu_abort (cpu_single_env, "goldfish_audio_write: Bad offset %x\n", offset);
    }
}

static CPUReadMemoryFunc *goldfish_battery_readfn[] = {
    goldfish_battery_read,
    goldfish_battery_read,
    goldfish_battery_read
};

static CPUWriteMemoryFunc *goldfish_battery_writefn[] = {
    goldfish_battery_write,
    goldfish_battery_write,
    goldfish_battery_write
};

void goldfish_battery_set_prop(void *opaque, int ac, int property, int value)
{
    int new_status = (ac ? AC_STATUS_CHANGED : BATTERY_STATUS_CHANGED);
    GoldfishBatteryDevice *s = (GoldfishBatteryDevice *)opaque;

    if (ac) {
        switch (property) {
            case POWER_SUPPLY_PROP_ONLINE:
                s->ac_online = value;
                break;
        }
    } else {
         switch (property) {
            case POWER_SUPPLY_PROP_STATUS:
                s->status = value;
                break;
            case POWER_SUPPLY_PROP_HEALTH:
                s->health = value;
                break;
            case POWER_SUPPLY_PROP_PRESENT:
                s->present = value;
                break;
            case POWER_SUPPLY_PROP_CAPACITY:
                s->capacity = value;
                break;
        }
    }

    if (new_status != s->int_status) {
        s->int_status |= new_status;
        goldfish_device_set_irq(&s->dev, 0, (s->int_status & s->int_enable));
    }
}

void goldfish_battery_display(void *opaque, void (* callback)(void *data, const char* string), void *data)
{
    GoldfishBatteryDevice *s = (GoldfishBatteryDevice *)opaque;
    char          buffer[100];
    const char*   value;

    sprintf(buffer, "AC: %s\r\n", (s->ac_online ? "online" : "offline"));
    callback(data, buffer);

    switch (s->status) {
	    case POWER_SUPPLY_STATUS_CHARGING:
	        value = "Charging";
	        break;
	    case POWER_SUPPLY_STATUS_DISCHARGING:
	        value = "Discharging";
	        break;
	    case POWER_SUPPLY_STATUS_NOT_CHARGING:
	        value = "Not charging";
	        break;
	    case POWER_SUPPLY_STATUS_FULL:
	        value = "Full";
	        break;
        default:
	        value = "Unknown";
	        break;
    }
    sprintf(buffer, "status: %s\r\n", value);
    callback(data, buffer);

    switch (s->health) {
	    case POWER_SUPPLY_HEALTH_GOOD:
	        value = "Good";
	        break;
	    case POWER_SUPPLY_HEALTH_OVERHEAT:
	        value = "Overhead";
	        break;
	    case POWER_SUPPLY_HEALTH_DEAD:
	        value = "Dead";
	        break;
	    case POWER_SUPPLY_HEALTH_OVERVOLTAGE:
	        value = "Overvoltage";
	        break;
	    case POWER_SUPPLY_HEALTH_UNSPEC_FAILURE:
	        value = "Unspecified failure";
	        break;
        default:
	        value = "Unknown";
	        break;
    }
    sprintf(buffer, "health: %s\r\n", value);
    callback(data, buffer);

    sprintf(buffer, "present: %s\r\n", (s->present ? "true" : "false"));
    callback(data, buffer);

    sprintf(buffer, "capacity: %d\r\n", s->capacity);
    callback(data, buffer);
}

static int goldfish_battery_init(GoldfishDevice *dev)
{
    return 0;
}

DeviceState *goldfish_battery_create(GoldfishBus *gbus)
{
    DeviceState *dev;
    char *name = (char *)"goldfish-battery";

    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_init_nofail(dev);

    return dev;
}

static GoldfishDeviceInfo goldfish_battery_info = {
    .init = goldfish_battery_init,
    .readfn = goldfish_battery_readfn,
    .writefn = goldfish_battery_writefn,
    .qdev.name  = "goldfish-battery",
    .qdev.size  = sizeof(GoldfishBatteryDevice),
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("base", GoldfishDevice, base, 0),
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, 0),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x1000),
        DEFINE_PROP_UINT32("irq", GoldfishDevice, irq, 0),
        DEFINE_PROP_UINT32("irq_count", GoldfishDevice, irq_count, 1),
        DEFINE_PROP_INT32("ac_online", GoldfishBatteryDevice, ac_online, 1),
        DEFINE_PROP_INT32("status", GoldfishBatteryDevice, status, POWER_SUPPLY_STATUS_CHARGING),
        DEFINE_PROP_INT32("health", GoldfishBatteryDevice, health, POWER_SUPPLY_HEALTH_GOOD),
        DEFINE_PROP_INT32("present", GoldfishBatteryDevice, present, 1),    // battery is present
        DEFINE_PROP_INT32("capacity", GoldfishBatteryDevice, capacity, 50), // 50% charged
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_battery_register(void)
{
    goldfish_bus_register_withprop(&goldfish_battery_info);
}
device_init(goldfish_battery_register);
