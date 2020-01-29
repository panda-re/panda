/*
 * Avatar2 basic machine for dynamic creation of emulated boards
 *
 * Copyright (C) 2017 Eurecom
 * Written by Dario Nisi, Marius Muench & Jonas Zaddach
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * This code is derived from versatilepb.c:
 *   ARM Versatile Platform/Application Baseboard System emulation.
 *   Copyright (c) 2005-2007 CodeSourcery.
 *   Written by Paul Brook
 */

//general imports
#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "exec/address-spaces.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/devices.h"
#include "hw/boards.h"

//plattform specific imports
#include "target/arm/cpu.h"
#include "hw/arm/arm.h"
#include "hw/avatar/arm_helper.h"

//qapi imports
#include "qapi/error.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qdict.h"

static inline void set_feature(CPUARMState *env, int feature)
{
    env->features |= 1ULL << feature;
}

static void board_init(MachineState * ms)
{
    const char *cpu_model = ms->cpu_model;
    ObjectClass *cpu_oc;
    Object *cpuobj;
    ARMCPU *cpuu;
    CPUState *env;
    cpu_model = "arm926";

    printf("Configurable: Adding processor %s\n", cpu_model);

    cpu_oc = cpu_class_by_name(TYPE_ARM_CPU, cpu_model);
    if (!cpu_oc) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    cpuobj = object_new(object_class_get_name(cpu_oc));

    object_property_set_bool(cpuobj, true, "realized", &error_fatal);
    cpuu = ARM_CPU(cpuobj);
    env = (CPUState *) &(cpuu->env);
    if (!env)
    {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    // Use avatar helpers to create CPU
    avatar_add_banked_registers(cpuu);
    set_feature(&cpuu->env, ARM_FEATURE_CONFIGURABLE);

}

static void basic_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Basic machine with just a CPU";
    mc->init = board_init;
    mc->block_default_type = IF_SCSI;
}

static const TypeInfo basic_machine_type = {
    .name       =  MACHINE_TYPE_NAME("basic"),
    .parent     = TYPE_MACHINE,
    .class_init = basic_machine_class_init,
};

static void basic_machine_init(void)
{
    type_register_static(&basic_machine_type);
}

type_init(basic_machine_init);
