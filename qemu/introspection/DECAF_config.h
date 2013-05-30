/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

/**
 * LOK: Should be auto generated?
**/

#ifndef DECAF_CONFIG_H
#define DECAF_CONFIG_H

#define QEMU_ANDROID_GINGERBREAD

#define REGISTER_SAVEVM(_1, _2, _3, _4, _5, _6, _7) register_savevm(_2, _3, _4, _5, _6, _7)

#define UNREGISTER_SAVEVM(_1, _2, _3) unregister_savevm(_2,_3)

#include "DECAF_mon_cmds_defs.h"
#include "exec-all.h"

#define KERNEL_START_ADDRESS (0xC0000000)
#define IS_USERSPACE_ADDR(_addr) (_addr < KERNEL_START_ADDRESS)
#define IS_KERNELSPACE_ADDR(_addr) (_addr >= KERNEL_START_ADDRESS)

#endif//DECAF_CONFIG_H
