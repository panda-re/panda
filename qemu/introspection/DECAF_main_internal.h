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

#ifndef _DECAF_MAIN_INTERNAL_H_
#define _DECAF_MAIN_INTERNAL_H_

#include "monitor.h"

//LOK: Separate data structure for DECAF commands and plugin commands
extern mon_cmd_t DECAF_mon_cmds[];
extern mon_cmd_t DECAF_info_cmds[];

/****** Functions used internally ******/
extern void DECAF_nic_receive(const uint8_t * buf, int size, int cur_pos, int start, int stop);
extern void DECAF_nic_send(uint32_t addr, int size, uint8_t * buf);
extern void DECAF_nic_in(uint32_t addr, int size);
extern void DECAF_nic_out(uint32_t addr, int size);
//LOK: Removed this extern void DECAF_read_keystroke(void *s);
extern void DECAF_virtdev_init(void);
extern void DECAF_after_loadvm(const char *); // AWH void);
extern void DECAF_init(void);

#if 0 //LOK: Removed these for the new callback interface
extern int TEMU_block_begin(void);
extern void TEMU_insn_begin(uint32_t pc_start);
extern void TEMU_insn_end(void);
extern void TEMU_block_end(void);
#endif

#ifdef TEMU_LD_PHYS_CB
extern void TEMU_ld_phys_cb(target_ulong addr, int size);
#endif
#ifdef TEMU_ST_PHYS_CB
extern void TEMU_st_phys_cb(target_ulong addr, int size);
#endif

extern void DECAF_update_cpl(int cpl);
extern void DECAF_do_interrupt(int intno, int is_int, target_ulong next_eip);
extern void DECAF_after_iret_protected(void);
//extern void TEMU_update_cpustate(void);
extern void DECAF_loadvm(void *opaque);

#endif //_TEMU_MAIN_INTERNAL_H_
