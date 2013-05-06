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
 * @date 12 OCT 2012
 */

#ifndef DECAF_CALLBACK_COMMON_H
#define DECAF_CALLBACK_COMMON_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "exec-all.h"
#include "DECAF_shared/DECAF_types.h"

//#include "test_tlb_cb.h"

typedef enum {
  DECAF_BLOCK_BEGIN_CB = 0,
  DECAF_BLOCK_END_CB,
  DECAF_INSN_BEGIN_CB,
  DECAF_INSN_END_CB,

  DECAF_SYSCALL_CB,
  DECAF_PGD_WRITE_CB,

  DECAF_LAST_CB, //place holder for the last position, no other uses.
} DECAF_callback_type_t;


//Optimized Callback type
typedef enum _OCB_t {
  /**
   * Optimized Callback Condition - Const - The value associated with this flag needs an exact match
   */
  OCB_CONST = 2,
  /**
   * Optimized callback Condition - Page - A match is found as long as the page numbers match
   */
  OCB_PAGE = 4,
  /**
   * Not used yet
   */
  OCB_CONST_NOT = 3,
  /**
   * Not used yet
   */
  OCB_PAGE_NOT = 5,
  /**
   * Optimized Callback Condition - Everything!
   */
  OCB_ALL = -1
} OCB_t;

typedef struct _DECAF_Block_Begin_Params
{
  CPUState* env;
  gva_t cur_pc;
  TranslationBlock* tb;
} DECAF_Block_Begin_Params;

typedef struct _DECAF_Block_End_Params
{
  CPUState* env;
  gva_t cur_pc;
  TranslationBlock* tb;
  //THIS IS A PC value - NOT EIP!!!!
  gva_t next_pc;
} DECAF_Block_End_Params;

typedef struct _DECAF_Insn_Begin_Params
{
  CPUState* env;
  gva_t cur_pc;
} DECAF_Insn_Begin_Params;

typedef struct _DECAF_Insn_End_Params
{
  CPUState* env;
  gva_t cur_pc;
} DECAF_Insn_End_Params;

typedef struct _DECAF_Syscall_Params
{
  CPUState* env;
  gva_t cur_pc;
  target_ulong syscall_num;
} DECAF_Syscall_Params;

typedef struct _DECAF_PGD_Write_Params
{
  CPUState* env;
  gpa_t curPGD;
  gpa_t newPGD;
  #ifdef TARGET_ARM
  enum {C2_BASE0 = 0, C2_BASE1 = 1} c2_base;
  #endif
} DECAF_PGD_Write_Params;

//LOK: A dummy type
typedef union _DECAF_Callback_Params
{
  DECAF_Block_Begin_Params bb;
  DECAF_Block_End_Params be;
  DECAF_Insn_Begin_Params ib;
  DECAF_Insn_End_Params ie;

  DECAF_Syscall_Params sc;
  DECAF_PGD_Write_Params pgd;
} DECAF_Callback_Params;

typedef void (*DECAF_callback_func_t)(DECAF_Callback_Params*);
//cur_pc
//next_pc is only used for block ends so far, it is most likely INV_ADDR
typedef int (*DECAF_cond_func_t) (DECAF_callback_type_t, gva_t cur_pc, gva_t next_pc);

#ifdef __cplusplus
}
#endif

#endif//DECAF_CALLBACK_COMMON_H
