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
#include "boards.h"
#include "devices.h"
#include "net.h"
#include "sysemu.h"
#include "goldfish_device.h"
#include "audio/audio.h"
#include "arm-misc.h"
#include "console.h"
#ifdef CONFIG_MEMCHECK
#include "memcheck/memcheck_api.h"
#endif  // CONFIG_MEMCHECK
#include "android/android.h"

#include "android/boot-properties.h"

/* Board init.  */

static struct arm_boot_info info = {
    .loader_start = 0x0,
    .board_id = 1441,
};

#define TEST_SWITCH 0
#if TEST_SWITCH
static uint32_t switch_test_write(void *opaque, uint32_t state)
{
    goldfish_switch_set_state(opaque, state);
    return state;
}
#endif

// we only have one machine, with one block of RAM. Track it for automatic replay configuration
static ram_addr_t ram_offset;
static void init_ram(ram_addr_t ram_size){
    ram_offset = qemu_ram_alloc(NULL, "android_arm", ram_size);
    cpu_register_physical_memory(0, ram_size, ram_offset | IO_MEM_RAM);
}

static void android_arm_init_(ram_addr_t ram_size,
    const char *boot_device,
    const char *kernel_filename,
    const char *kernel_cmdline,
    const char *initrd_filename,
    const char *cpu_model)
{
    CPUState *env;
    qemu_irq *cpu_pic;
    DeviceState *gf_int;
    int i;

    if (!cpu_model)
        cpu_model = "arm926";

    env = cpu_init(cpu_model);

    init_ram(ram_size);

    cpu_pic = arm_pic_init_cpu(env);
    GoldfishBus *gbus = goldfish_bus_init(0xff001000, 1);
    gf_int = goldfish_int_create(gbus, 0xff000000, cpu_pic[ARM_PIC_CPU_IRQ], cpu_pic[ARM_PIC_CPU_FIQ]);
    goldfish_device_init(gf_int, 0xff010000, 10);
    goldfish_timer_create(gbus, 0xff003000, 3);
    goldfish_rtc_create(gbus);
    goldfish_tty_create(gbus, serial_hds[0], 0, 0xff002000, 4);
    for(i = 1; i < MAX_SERIAL_PORTS; i++) {
        printf("android_arm_init serial %d %x\n", i, serial_hds[i]);
        if(serial_hds[i]) {
            printf("serial_hds: %d\n",i);
            goldfish_tty_create(gbus, serial_hds[i], i, 0, 0);
        }
    }

    for(i = 0; i < MAX_NICS; i++) {
        if (nd_table[i].vlan) {
            if (nd_table[i].model == NULL
                || strcmp(nd_table[i].model, "smc91c111") == 0) {
                GoldfishDevice *smc_device;
                smc_device = g_malloc0(sizeof(*smc_device));
                smc_device->name = (char *)"smc91x";
                smc_device->id = i;
                smc_device->size = 0x1000;
                smc_device->irq_count = 1;
                goldfish_add_device_no_io(smc_device);
                smc91c111_init(&nd_table[i], smc_device->base, qdev_get_gpio_in(gf_int, smc_device->irq));
            } else {
                fprintf(stderr, "qemu: Unsupported NIC: %s\n", nd_table[0].model);
                exit (1);
            }
        }
    }

    goldfish_fb_create(gbus, 0);
#ifdef HAS_AUDIO
    //goldfish_audio_init(0xff004000, 0, audio_input_source);
#endif

    goldfish_mmc_create(gbus, 0xff005000, 0);
    goldfish_memlog_create(gbus, 0xff006000);
    goldfish_battery_create(gbus);
    goldfish_events_create(gbus, gf_int);
    goldfish_nand_create(gbus);
    goldfish_pipe_create(gbus);

#if TEST_SWITCH
    {
        void *sw;
        sw = goldfish_switch_create(gbus, "test", NULL, NULL, 0);
        goldfish_switch_set_state(sw, 1);
        goldfish_switch_create(gbus, "test2", switch_test_write, sw, 1);
    }
#endif

    info.ram_size        = ram_size;
    info.kernel_filename = kernel_filename;
    info.kernel_cmdline  = kernel_cmdline;
    info.initrd_filename = initrd_filename;
    info.nb_cpus         = 1;

    arm_load_kernel(env, &info);
    android_emulation_setup();
}

QEMUMachine android_arm_machine = {
    .name = "android_arm",
    .desc = "ARM Android Emulator",
    .init = android_arm_init_,
    .use_scsi = 0,
    .max_cpus = 0,
    .is_default = 0,
    .next = NULL
};

void android_arm_resize_ram(ram_addr_t new_size){
    assert(current_machine->init == android_arm_init_);
    qemu_ram_free(ram_offset); // RAM starts at address 0
    init_ram(new_size);
}

static void android_arm_init(void)
{
    qemu_register_machine(&android_arm_machine);
}

machine_init(android_arm_init);
