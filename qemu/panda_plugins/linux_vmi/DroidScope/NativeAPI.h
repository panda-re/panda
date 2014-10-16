/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * NativeAPI.h
 *
 *  Created on: Oct 6, 2011
 *      Author: lok
 */

#ifndef NATIVEAPI_H_
#define NATIVEAPI_H_

#include "DS_Common.h"

/******************************************************************************
 * TYPES
 *****************************************************************************/

typedef enum {
        MEM_TYPE_REG = 0,
        MEM_TYPE_MEM = 1
} addr_type;

#define ARM_MAX_OPERANDS 20

typedef struct {
        uint32_t deadbeef;
        uint64_t entry_num;
        uint32_t eip;
        uint32_t insn;
        uint32_t read_opers;
        uint32_t write_opers;
} InsnHeader;

typedef struct {
        addr_type type;
        uint32_t addr;
        uint32_t val;
        uint32_t size;
} InsnOperand;

typedef struct {
        InsnHeader header;
        InsnOperand read[ARM_MAX_OPERANDS];
        InsnOperand write[ARM_MAX_OPERANDS];
} InsnEntry;

/******************************************************************************
 * CONTROL API SECTION
 *****************************************************************************/

/**
 * Pause the VM with code 0x10000 which is EXCP_INTERRUPT. This is the same one used for the "stop" qemu monitor command
 */
//static inline void pause_vm() { vm_stop(0x10000); }

/******************************************************************************
 * ACCESS API SECTION
 *****************************************************************************/

/**
 * used to get the base address - equivalent of the CR3 for ARM.
 * Note that because ARM has two base addresses (e.g. 2 PGDs) we need the virtual address in question
 *   to help determine which of the two tables should be used. Most of the time (if not all) it should
 *   be the 1st one, i.e. c2_base0
 * @param env The context
 * @param address The virtual address we are looking at.
 */
uint32_t get_table_base_address(CPUState *env, gva_t address);

#endif /* NATIVEAPI_H_ */
