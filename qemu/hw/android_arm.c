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

/* Board init.  */

static struct arm_boot_info info = {
    .loader_start = 0x0,
    .board_id = 1441,
};

static void android_arm_init_(ram_addr_t ram_size,
    const char *boot_device,
    const char *kernel_filename,
    const char *kernel_cmdline,
    const char *initrd_filename,
    const char *cpu_model)
{
    CPUState *env;
    qemu_irq *cpu_pic;
    ram_addr_t ram_offset;
    DeviceState *gf_int;

    if (!cpu_model)
        cpu_model = "arm926";

    env = cpu_init(cpu_model);

    ram_offset = qemu_ram_alloc(NULL,"android_arm",ram_size);
    cpu_register_physical_memory(0, ram_size, ram_offset | IO_MEM_RAM);

    cpu_pic = arm_pic_init_cpu(env);
    GoldfishBus *gbus = goldfish_bus_init(0xff001000, 1);
    gf_int = goldfish_int_create(gbus, 0xff000000, cpu_pic[ARM_PIC_CPU_IRQ], cpu_pic[ARM_PIC_CPU_FIQ]);
    goldfish_device_init(gf_int, 0xff010000, 10);

    info.ram_size        = ram_size;
    info.kernel_filename = kernel_filename;
    info.kernel_cmdline  = kernel_cmdline;
    info.initrd_filename = initrd_filename;
    info.nb_cpus         = 1;

    arm_load_kernel(env, &info);
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

static void android_arm_init(void)
{
    qemu_register_machine(&android_arm_machine);
}

machine_init(android_arm_init);
