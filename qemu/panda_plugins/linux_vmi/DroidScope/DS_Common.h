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

/**
 * @author Lok Yan
 * @date 9/28/2011
 */

#ifndef DS_COMMON_H
#define DS_COMMON_H

//#include <inttypes.h>
//#include <stdio.h>
//#include "cpu.h"
#include "linux_vmi_types.h"

typedef enum {
  LOG_LEVEL_MINIMAL,
  LOG_LEVEL_SIMPLE,
  LOG_LEVEL_VERBOSE,
  LOG_LEVEL_EVERYTHING
} LogLevel;

/**
 * Strips the last bit of the link-register.
 * Remember that if bit 1 is 1 then the previous instruction was thumb, else it is not
 */
#define lp_strip(_lp) (_lp & ~0x1)

//There is some documentation that says that the PGDs for ARM must be 16k aligned - but we will just assume that they are 4k aligned and use that for stripping
//#define pgd_strip(_pgd) (_pgd & ~0xC0000000)
#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)

/**
 * Linux uses 4K pages but QEMU for ARM is setup to use 1k pages.
 */
#define LINUX_PAGE_BITS 12
#define LINUX_PAGE_SIZE ( 1 << LINUX_PAGE_BITS )
#define LINUX_OFFSET_MASK ( LINUX_PAGE_SIZE - 1 )
#define LINUX_PAGE_MASK ( ~LINUX_OFFSET_MASK )

#define SET_TASK_COMM_ADDR 0xc0090ab8 //0xc0091694
#define DO_FORK_ADDR 0xc003e184 //0xc003cdb8 //0xc0039184 //0xc0026f7c
#define DO_EXECVE_ADDR 0xc0096a18 // 0xc0091770 //0xc0092530
#define DO_MMAP2_ADDR 0xc002b030 //0xc0026030 //0xc0027030
#define DO_PRCTL_ADDR 0xc0046bf8 //0xc004939c
#define DO_CLONE_ADDR 0xc0025ea8 //0xc0026f40

#define DVM_JIT_GET_CODE_ADDR (0x800742d8) //(0xACA6D794)
#define DVM_ASM_INSTRUCTION_START (0x80018040) //(0xaca11f40)

#define DVM_COMPILER_PERFORM_SAFE_POINT_CHECKS (0x80071790) //(0xaca6ac10)

//0xa2ad0 -- offset of gDvmJit
//0xacaa2ad0 -- address of?
#define G_DVM_JIT (0xacaa2ad0)

//now the offset to the codecachefull thing is 100
//0xacaa2ad0 + 100 = acaa2b34
#define CODE_CACHE_FULL_OFFSET (100)
#define G_DVM_JIT_CODE_CACHE_FULL (G_DVM_JIT + CODE_CACHE_FULL_OFFSET)

#endif//DS_COMMON_H
