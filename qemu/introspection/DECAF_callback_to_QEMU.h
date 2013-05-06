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
 * @author Lok Yan
 * @date 9 Oct 2012
 * Explicit declaration of prototypes between DECAF callbacks and QEMU. This includes all of the
 *   helper functions
 */

#ifndef DECAF_CALLBACK_TO_QEMU_H
#define DECAF_CALLBACK_TO_QEMU_H

#ifdef __cplusplus
extern "C"
{
#endif

// #include "cpu.h" //Not needed - included in DECAF_callback_common.h
// #include "DECAF_shared/DECAF_types.h" // not needed either
#include "DECAF_shared/DECAF_callback_common.h"

int DECAF_is_callback_needed(DECAF_callback_type_t cb_type, gva_t cur_pc, gva_t next_pc);
int DECAF_is_BlockBeginCallback_needed(gva_t cur_pc);
int DECAF_is_BlockEndCallback_needed(gva_t from, gva_t to);

//The following prototypes are not needed since they are defined in
// helper.h
//void helper_DECAF_invoke_block_begin_callback(CPUState* env, TranslationBlock* tb);
//void helper_DECAF_invoke_block_end_callback(CPUState* env, TranslationBlock* tb, gva_t from, gva_t to);
//void helper_DECAF_invoke_insn_begin_callback(CPUState* env);
//void helper_DECAF_invoke_insn_begin_callback(CPUState* env);

#ifdef __cplusplus
}
#endif

#endif//DECAF_CALLBACK_TO_QEMU_H
