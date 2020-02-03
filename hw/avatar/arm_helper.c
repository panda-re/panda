/*
 * Avatar2 helper functions for configurable machines using ARM
 *
 * Copyright (C) 2017 Eurecom
 * Written by Marius Muench
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
 */

#include "qemu/osdep.h"
#include "exec/address-spaces.h"
#include "exec/gdbstub.h"

#include "internals.h"

#include "hw/avatar/arm_helper.h"

static int banked_gdb_set_reg(CPUARMState *env, uint8_t *buf, int reg){
    switch (reg) {
    case 0:
        env->banked_r13[bank_number(ARM_CPU_MODE_USR)] = ldl_p(buf); return 4;
    case 1:
        env->banked_r14[bank_number(ARM_CPU_MODE_USR)] = ldl_p(buf); return 4;
    case 2:
        env->fiq_regs[0] = ldl_p(buf); return 4;
    case 3:
        env->fiq_regs[1] = ldl_p(buf); return 4;
    case 4:
        env->fiq_regs[2] = ldl_p(buf); return 4;
    case 5:
        env->fiq_regs[3] = ldl_p(buf); return 4;
    case 6:
        env->fiq_regs[4] = ldl_p(buf); return 4;
    case 7:
        env->banked_r13[bank_number(ARM_CPU_MODE_FIQ)] = ldl_p(buf); return 4;
    case 8:
        env->banked_r14[bank_number(ARM_CPU_MODE_FIQ)] = ldl_p(buf); return 4;
    case 9:
        env->banked_r13[bank_number(ARM_CPU_MODE_IRQ)] = ldl_p(buf); return 4;
    case 10:
        env->banked_r14[bank_number(ARM_CPU_MODE_IRQ)] = ldl_p(buf); return 4;
    case 11:
        env->banked_r13[bank_number(ARM_CPU_MODE_SVC)] = ldl_p(buf); return 4;
    case 12:
        env->banked_r14[bank_number(ARM_CPU_MODE_SVC)] = ldl_p(buf); return 4;
    case 13:
        env->banked_r13[bank_number(ARM_CPU_MODE_ABT)] = ldl_p(buf); return 4;
    case 14:
        env->banked_r14[bank_number(ARM_CPU_MODE_ABT)] = ldl_p(buf); return 4;
    case 15:
        env->banked_r13[bank_number(ARM_CPU_MODE_UND)] = ldl_p(buf); return 4;
    case 16:
        env->banked_r14[bank_number(ARM_CPU_MODE_UND)] = ldl_p(buf); return 4;
    case 17:
        env->banked_spsr[BANK_FIQ] = ldl_p(buf); return 4;
    case 18:
        env->banked_spsr[BANK_IRQ] = ldl_p(buf); return 4;
    case 19:
        env->banked_spsr[BANK_SVC] = ldl_p(buf); return 4;
    case 20:
        env->banked_spsr[BANK_ABT] = ldl_p(buf); return 4;
    case 21:
        env->banked_spsr[BANK_UND] = ldl_p(buf); return 4;
    }
    return 0;
}

static int banked_gdb_get_reg(CPUARMState *env, uint8_t *buf, int reg)
{
    switch(reg){
    case 0:
        stl_p(buf, env->banked_r13[bank_number(ARM_CPU_MODE_USR)]); return 4;
    case 1:
        stl_p(buf, env->banked_r14[bank_number(ARM_CPU_MODE_USR)]); return 4;
    case 2:
        stl_p(buf, env->fiq_regs[0]); return 4;
    case 3:
        stl_p(buf, env->fiq_regs[1]); return 4;
    case 4:
        stl_p(buf, env->fiq_regs[2]); return 4;
    case 5:
        stl_p(buf, env->fiq_regs[3]); return 4;
    case 6:
        stl_p(buf, env->fiq_regs[4]); return 4;
    case 7:
        stl_p(buf, env->banked_r13[bank_number(ARM_CPU_MODE_FIQ)]); return 4;
    case 8:
        stl_p(buf, env->banked_r14[bank_number(ARM_CPU_MODE_FIQ)]); return 4;
    case 9:
        stl_p(buf, env->banked_r13[bank_number(ARM_CPU_MODE_IRQ)]); return 4;
    case 10:
        stl_p(buf, env->banked_r14[bank_number(ARM_CPU_MODE_IRQ)]); return 4;
    case 11:
        stl_p(buf, env->banked_r13[bank_number(ARM_CPU_MODE_SVC)]); return 4;
    case 12:
        stl_p(buf, env->banked_r14[bank_number(ARM_CPU_MODE_SVC)]); return 4;
    case 13:
        stl_p(buf, env->banked_r13[bank_number(ARM_CPU_MODE_ABT)]); return 4;
    case 14:
        stl_p(buf, env->banked_r14[bank_number(ARM_CPU_MODE_ABT)]); return 4;
    case 15:
        stl_p(buf, env->banked_r13[bank_number(ARM_CPU_MODE_UND)]); return 4;
    case 16:
        stl_p(buf, env->banked_r14[bank_number(ARM_CPU_MODE_UND)]); return 4;
    case 17:
        stl_p(buf, env->banked_spsr[BANK_FIQ]); return 4;
    case 18:
        stl_p(buf, env->banked_spsr[BANK_IRQ]); return 4;
    case 19:
        stl_p(buf, env->banked_spsr[BANK_SVC]); return 4;
    case 20:
        stl_p(buf, env->banked_spsr[BANK_ABT]); return 4;
    case 21:
        stl_p(buf, env->banked_spsr[BANK_UND]); return 4;
    }
    return 0;
}


void avatar_add_banked_registers(ARMCPU *cpu){
    CPUState *cs = CPU(cpu);
    gdb_register_coprocessor(cs, banked_gdb_get_reg, banked_gdb_set_reg,
            21, "arm-banked.xml", 0);
}
