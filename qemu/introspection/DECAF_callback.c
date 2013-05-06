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

/*
 * DECAF_callback.c
 *
 *  Created on: Apr 10, 2012
 *      Author: heyin@syr.edu
 *  LOK: Overhauled on 25 DEC 2012
 * 
 */
#include <sys/queue.h>
#include <stdio.h>
#include <inttypes.h>
#include "qemu-common.h"
#include "cpu-all.h"
#include "DECAF_shared/DECAF_main.h"
#include "DECAF_shared/DECAF_callback.h"
#include "DECAF_shared/DECAF_callback_to_QEMU.h"
#include "DECAF_shared/utils/HashtableWrapper.h"

//LOK: The callback logic is separated into two parts
//  1. the interface between QEMU and callback
//    this is invoked during translation time
//  2. the interface between the callback and the plugins
//    this is invoked during execution time
//The basic idea is to provide a rich interface for users
//  while abstracting and hiding all of the details

//Currently we support callbacks for instruction begin/end and
// basic block begin and end. Basic block level callbacks can
// also be optimized. There are two types of optimized callbacks
// constant (OCB_CONST) and page (OCB_PAGE). The idea begin
// the constant optimized callback type is that
// function level hooking only needs to know when the function
// starts and returns, both of which are hard target addresses.
//The idea behind the page level callback is for API level
// instrumentation where modules are normally separated at the
// page level. Block end callbacks are a little bit special
// since the callback can be set for both the from and to
// addresses. In this way, you can specify callbacks only for
// the transitions between a target module and the libc library
// for example. For simplicity sake we only provide page-level optimized
// callback support for block ends. Supporting it at the individual
// address level seemed like overkill - n^2 possible combinations.
//Todo: Future implementations should include support for the NOT
// condition for the optimized callbacks. This capability can be used
// for specifying all transitions from outside of a module into a module.
// for example it would be specified as block end callbacks where from
// is NOT module_page and to is module_page.


//We begin by declaring the necessary data structures
// for determining whether a callback is necessary
//These are declared if all block begins and ends
// are needed.
static int bEnableAllBlockBeginCallbacks = 0;
//We keep a count of the number of registered callbacks that
// need all of the block begins and ends so that we can turn
// on or off the optimized callback interface. The complete
// translation cache is flushed when the count goes from 0 to 1
// and from 1 downto 0
static int enableAllBlockBeginCallbacksCount = 0;
static int bEnableAllBlockEndCallbacks = 0;
static int enableAllBlockEndCallbacksCount = 0;


//We use hashtables to keep track of individual basic blocks
// that is associated with a callback - we ignore
// the conditional that is registered with the callback 
// right now - that is the conditional has been changed
// into a simple "enable" bit. The reasoning is that the condition is controlled
// by the user, and so there is no way for us to update
// the hashtables accordingly.
//Specifically, we use a counting hashtable (essentially a hashmap)
// where the value is the number of callbacks that have registered for
// this particular condition. The affected translation block
// is flushed at the 0 to 1 or 1 to 0 transitions.
static CountingHashtable* pOBBTable;

//A second page table at the page level
//There are two different hashtables so that determining
// whether a callback is needed at translation time (stage 1)
// can be done in the order of - allBlockBegins, Page level and then
// individual address or constant level.
static CountingHashtable* pOBBPageTable;

//Similarly we declare hashtables for block end
// the unique aspect of these hashtables is that they are
// only defined at the page level AND they are defined
// for the block end source (i.e. the location of the current
// basic block), the block end target (i.e. where is the next
// basic block), and then a map that contains both.

//This first table is for block ends callbacks that only specify the
// from address - i.e. where the block currently is
static CountingHashtable* pOBEFromPageTable;

//This second table is for callbacks that only specify the to address
// that is where the next block is
static CountingHashtable* pOBEToPageTable;

//This third table is for callbacks that specify both the from and to
// addresses. The hashmap maps the "from" page to a hashtable of "to" pages
static CountingHashmap* pOBEPageMap;


//data structures for storing the userspace callbacks (stage 2)
typedef struct callback_struct{
	//the following are used by the optimized callbacks
	//BlockBegin only uses from - to is ignored
	//blockend uses both from and to
	gva_t from;
	gva_t to;
	OCB_t ocb_type;
        DECAF_cond_func_t cb_cond_func;
	DECAF_callback_func_t callback;

	LIST_ENTRY(callback_struct) link;
}callback_struct_t;

//Each type of callback has its own callback_list
// The callback list is used to maintain the list of registered callbacks
// as well as their conditions. In essense, this data structure
// is used for interfacing with the user (stage 2)
static LIST_HEAD(callback_list_head, callback_struct) callback_list_heads[DECAF_LAST_CB];


//iterate through the appropriate list and return true if 
// either cb_cond_func is NULL or if the user function returns
// true
int DECAF_is_callback_needed(DECAF_callback_type_t cb_type, gva_t cur_pc, gva_t next_pc)
{
  callback_struct_t *cb_struct;

  if (cb_type >= DECAF_LAST_CB)
  {
    return (0);
  }

  LIST_FOREACH(cb_struct, &callback_list_heads[cb_type], link) 
  {
    DEFENSIVE_CHECK1(cb_struct == NULL, 0);

    if (cb_struct->cb_cond_func == NULL)
    {
      return (1);
    }
    if (cb_struct->cb_cond_func(cb_type, cur_pc, next_pc))
    {
      return (1);
    }
  }    
  return (0);
}

//here we search from the broadest to the narrowest
// to determine whether the callback is needed
int DECAF_is_BlockBeginCallback_needed(gva_t pc)
{
  //go through the page list first
  if (bEnableAllBlockBeginCallbacks)
  {
    return (1);
  }

  //TODO: FIX THIS LOGIC It doesn't make sense
  // since we make the call here, it will never get down to the
  // other tests - because if there is OBBPage or wahtever
  // then the callback function is going to be NULL
  // which makes this return 1.
  if (DECAF_is_callback_needed(DECAF_BLOCK_BEGIN_CB, pc, INV_ADDR))
  {
    return (1);
  }

  if (CountingHashtable_exist(pOBBPageTable, pc & TARGET_PAGE_MASK))
  {
    return (1);
  }

  if (CountingHashtable_exist(pOBBTable, pc))
  {
    return (1);
  }

  return 0;
}

int DECAF_is_BlockEndCallback_needed(gva_t from, gva_t to)
{
  if (bEnableAllBlockEndCallbacks)
  {
    return (1);
  }

  if (DECAF_is_callback_needed(DECAF_BLOCK_END_CB, from, to))
  {
    return (1);
  }

  from &= TARGET_PAGE_MASK;
  //go through the page list first
  if (CountingHashtable_exist(pOBEFromPageTable, from))
  {
    return (1);
  }
  if (to == INV_ADDR) //this is a special case where the target is not known at translation time
  {
    return (0);
  }

  to &= TARGET_PAGE_MASK;
  if (CountingHashtable_exist(pOBEToPageTable, to))
  {
    return (1);
  }

  return (CountingHashmap_exist(pOBEPageMap, from, to));
}


DECAF_Handle DECAF_registerOptimizedBlockBeginCallback(
    DECAF_callback_func_t cb_func,
    gva_t addr,
    OCB_t type)
{

  callback_struct_t * cb_struct = (callback_struct_t *)malloc(sizeof(callback_struct_t));
  if (cb_struct == NULL)
  {
    return (DECAF_NULL_HANDLE);
  }

  //pre-populate the info
  cb_struct->callback = cb_func;
  cb_struct->from = addr;
  cb_struct->to = INV_ADDR;
  cb_struct->ocb_type = type;
  cb_struct->cb_cond_func = NULL;

  switch (type)
  {
    default:
    case (OCB_ALL):
    {
      //call the original
      bEnableAllBlockBeginCallbacks = 1;
      enableAllBlockBeginCallbacksCount++;

      //we need to flush if it just transitioned from 0 to 1
      if (enableAllBlockBeginCallbacksCount == 1)
      {
        //Perhaps we should flush ALL blocks instead of
        // just the ones associated with this env?
        DECAF_flushTranslationCache();
      }

      break;
    }
    case (OCB_CONST):
    {
      if (pOBBTable == NULL)
      {
        free(cb_struct);
        return (DECAF_NULL_HANDLE);
      }
      //This is not necessarily thread-safe
      if (CountingHashtable_add(pOBBTable, addr) == 1)
      {
        DECAF_flushTranslationBlock(addr);
      }
      break;
    }
    case (OCB_CONST_NOT):
    {
      break;
    }
    case (OCB_PAGE_NOT):
    {
      break;
    }
    case (OCB_PAGE):
    {
      addr &= TARGET_PAGE_MASK;
      if (pOBBPageTable == NULL)
      {
        free(cb_struct);
        return (DECAF_NULL_HANDLE);
      }

      //This is not necessarily thread-safe
      if (CountingHashtable_add(pOBBPageTable, addr) == 1)
      {
        //DECAF_flushTranslationPage(addr);
        DECAF_flushTranslationCache();
      }
      break;
    }
  }

  //insert it into the list
  LIST_INSERT_HEAD(&callback_list_heads[DECAF_BLOCK_BEGIN_CB], cb_struct, link);

  return ((DECAF_Handle)cb_struct);
}

DECAF_Handle DECAF_registerOptimizedBlockEndCallback(
    DECAF_callback_func_t cb_func,
    gva_t from,
    gva_t to)
{

  callback_struct_t * cb_struct = (callback_struct_t *)malloc(sizeof(callback_struct_t));
  if (cb_struct == NULL)
  {
    return (DECAF_NULL_HANDLE);
  }

  //pre-populate the info
  cb_struct->callback = cb_func;
  cb_struct->from = from;
  cb_struct->to = to;
  cb_struct->ocb_type = OCB_ALL;
  cb_struct->cb_cond_func = NULL;
  

  if ( (from == INV_ADDR) && (to == INV_ADDR) )
  {
    enableAllBlockEndCallbacksCount++;
    bEnableAllBlockEndCallbacks = 1;
    if (enableAllBlockEndCallbacksCount == 1)
    {
      DECAF_flushTranslationCache();
    }
  }
  else if (to == INV_ADDR) //this means only looking at the FROM list
  {
    if (pOBEFromPageTable == NULL)
    {
      free(cb_struct);
      return(DECAF_NULL_HANDLE);
    }

    if (CountingHashtable_add(pOBEFromPageTable, from & TARGET_PAGE_MASK) == 1)
    {
      DECAF_flushTranslationPage(from);
    }
  }
  else if (from == INV_ADDR)
    //this is tricky, because it involves flushing the WHOLE cache
  {
    if (pOBEToPageTable == NULL)
    {
      free(cb_struct);
      return(DECAF_NULL_HANDLE);
    }

    if (CountingHashtable_add(pOBEToPageTable, to & TARGET_PAGE_MASK) == 1)
    {
      DECAF_flushTranslationCache();
    }
  }
  else
  {
    if (pOBEPageMap == NULL)
    {
      free(cb_struct);
      return(DECAF_NULL_HANDLE);
    }

    //if we are here then that means we need the hashmap
    if (CountingHashmap_add(pOBEPageMap, from & TARGET_PAGE_MASK, to & TARGET_PAGE_MASK) == 1)
    {
      DECAF_flushTranslationPage(from);
    }
  }

  //insert into the list
  LIST_INSERT_HEAD(&callback_list_heads[DECAF_BLOCK_END_CB], cb_struct, link);
  return ((DECAF_Handle)cb_struct);
}

//this is for backwards compatibility -
// for block begin and end - we make a call to the optimized versions
// for insn begin and end we just use the old logic
// for mem read and write ,use the old logic
DECAF_Handle DECAF_register_callback(
		DECAF_callback_type_t cb_type,
		DECAF_callback_func_t cb_func,
		DECAF_cond_func_t cb_cond_func)
{
  if ( (cb_cond_func == NULL) && (DECAF_BLOCK_BEGIN_CB == cb_type) )
  {
    return(DECAF_registerOptimizedBlockBeginCallback(cb_func, INV_ADDR, OCB_ALL));
  }

  if ( (cb_cond_func == NULL) && (DECAF_BLOCK_END_CB == cb_type) )
  {
    return(DECAF_registerOptimizedBlockEndCallback(cb_func, INV_ADDR, INV_ADDR));
  }

  //if we are here then that means its either insn begin or end or that cb_cond_func was not NULL

  callback_struct_t * cb_struct =
      (callback_struct_t *)malloc(sizeof(callback_struct_t));

  if (cb_struct == NULL)
  {
    return (DECAF_NULL_HANDLE);
  }

  cb_struct->callback = cb_func;
  cb_struct->cb_cond_func = cb_cond_func;
  cb_struct->from = INV_ADDR;
  cb_struct->to = INV_ADDR;

  if(LIST_EMPTY(&callback_list_heads[cb_type]))
  {
    DECAF_flushTranslationCache();
  }

  LIST_INSERT_HEAD(&callback_list_heads[cb_type], cb_struct, link);

  return ((DECAF_Handle)cb_struct);
}


DECAF_errno_t DECAF_unregisterOptimizedBlockBeginCallback(DECAF_Handle handle)
{
  callback_struct_t *cb_struct;
  //to unregister the callback, we have to first find the
  // callback and its conditions and then remove it from the
  // corresonding hashtable

  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_BEGIN_CB], link) 
  {
    DEFENSIVE_CHECK1(cb_struct == NULL, NULL_POINTER_ERROR);

    if((DECAF_Handle)cb_struct != handle)
    {
      continue;
    }

    //now that we have found it - check out its conditions
    switch(cb_struct->ocb_type)
    {
      default: //same as ALL to match the register function
      case (OCB_ALL):
      {
        enableAllBlockBeginCallbacksCount--;
        if (enableAllBlockBeginCallbacksCount == 0)
        {
          bEnableAllBlockBeginCallbacks = 0;
          //if its now zero flush the cache
          DECAF_flushTranslationCache();
        }
        else if (enableAllBlockBeginCallbacksCount < 0)
        {
          //if it underflowed then reset to 0
          //this is really an error
          //notice I don't reset enableallblockbegincallbacks to 0
          // just in case
          enableAllBlockBeginCallbacksCount = 0;
        }
        break;
      }
      case (OCB_CONST):
      {
        if (pOBBTable == NULL)
        {
          return (NULL_POINTER_ERROR);
        }
        if (CountingHashtable_remove(pOBBTable, cb_struct->from) == 0)
        {
          DECAF_flushTranslationBlock(cb_struct->from);
        }
        break;
      }
      case (OCB_PAGE):
      {
        if (pOBBPageTable == NULL)
        {
          return (NULL_POINTER_ERROR);
        }
        if (CountingHashtable_remove(pOBBPageTable, cb_struct->from) == 0)
        {
          //DECAF_flushTranslationPage(cb_struct->from);
          DECAF_flushTranslationCache();
        }
        break;
      }
    }

    //now that we cleaned up the hashtables - we should remove the callback entry
    LIST_REMOVE(cb_struct, link);
    //and free the struct
    free(cb_struct);

    return 0;
  }

  return -1;
}


DECAF_errno_t DECAF_unregisterOptimizedBlockEndCallback(DECAF_Handle handle)
{
  callback_struct_t *cb_struct;

  //to unregister the callback, we have to first find the
  // callback and its conditions and then remove it from the
  // corresonding hashtable

  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_END_CB], link) 
  {
    DEFENSIVE_CHECK1(cb_struct == NULL, NULL_POINTER_ERROR);

    if((DECAF_Handle)cb_struct != handle)
    {
      continue;
    }

    if ( (cb_struct->from == INV_ADDR) && (cb_struct->to == INV_ADDR) )
    {
      enableAllBlockEndCallbacksCount--;
      if (enableAllBlockEndCallbacksCount == 0)
      {
        DECAF_flushTranslationCache();
        bEnableAllBlockEndCallbacks = 0;
      }
      else if (enableAllBlockEndCallbacksCount < 0)
      {
        //this is really an error
        enableAllBlockEndCallbacksCount = 0;
      }
    }
    else if (cb_struct->to == INV_ADDR)
    {
      gva_t from = cb_struct->from & TARGET_PAGE_MASK;
      if (CountingHashtable_remove(pOBEFromPageTable, from) == 0)
      {
        DECAF_flushTranslationPage(from);
      }
    }
    else if (cb_struct->from == INV_ADDR)
    {
      gva_t to = cb_struct->to & TARGET_PAGE_MASK;
      if (CountingHashtable_remove(pOBEToPageTable, to) == 0)
      {
        DECAF_flushTranslationCache();
      }
    }
    else if (CountingHashmap_remove(pOBEPageMap, cb_struct->from & TARGET_PAGE_MASK, cb_struct->to & TARGET_PAGE_MASK) == 0)
    {
      DECAF_flushTranslationPage(cb_struct->from & TARGET_PAGE_MASK);
    }

    //we can now remove the entry
    LIST_REMOVE(cb_struct, link);
    //and free the struct
    free(cb_struct);

    return 0;
  }

  return (-1);
}

DECAF_errno_t DECAF_unregister_callback(DECAF_callback_type_t cb_type, DECAF_Handle handle)
{
  if (cb_type == DECAF_BLOCK_BEGIN_CB)
  {
    return (DECAF_unregisterOptimizedBlockBeginCallback(handle));
  }
  else if (cb_type == DECAF_BLOCK_END_CB)
  {
    return (DECAF_unregisterOptimizedBlockEndCallback(handle));
  }

  callback_struct_t *cb_struct;
  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[cb_type], link)
  {
    DEFENSIVE_CHECK1(cb_struct == NULL, NULL_POINTER_ERROR);

    if ((DECAF_Handle)cb_struct != handle)
    {
      continue;
    }

    LIST_REMOVE(cb_struct, link);
    free(cb_struct);

    //Aravind - If going from non-empty to empty. Flush needed
    if (LIST_EMPTY(&callback_list_heads[cb_type]))
    {
      DECAF_flushTranslationCache();
    }

    return 0;
  }

  return -1;
}

void helper_DECAF_invoke_block_begin_callback(CPUState* env, TranslationBlock* tb, gva_t cur_pc)
{
  callback_struct_t *cb_struct;
  DECAF_Callback_Params params;

  DEFENSIVE_CHECK0((env == NULL) || (tb == NULL));

  params.bb.env = env;
  params.bb.cur_pc = cur_pc;
  params.bb.tb = tb;

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_BEGIN_CB], link) 
  {
    DEFENSIVE_CHECK0(cb_struct == NULL);

    // If it is a global callback or it is within the execution context,
    // invoke this callback
    switch (cb_struct->ocb_type)
    {
      default:
      case (OCB_ALL):
      {
        cb_struct->callback(&params);
        break;
      }
      case (OCB_CONST):
      {
        if (cb_struct->from == tb->pc)
        {
          cb_struct->callback(&params);
        }
        break;
      }
      case (OCB_PAGE):
      {
        if ((cb_struct->from & TARGET_PAGE_MASK) == (tb->pc & TARGET_PAGE_MASK))
        {
          cb_struct->callback(&params);
        }
        break;
      }
    }
  }
}

void helper_DECAF_invoke_block_end_callback(CPUState* env, TranslationBlock* tb, gva_t from, gva_t to)
{
  callback_struct_t *cb_struct;
  DECAF_Callback_Params params;

  DEFENSIVE_CHECK0(env == NULL);

  params.be.env = env;
  params.be.tb = tb;
  params.be.cur_pc = from;
  //params.be.next_pc = DECAF_getPC(env);
  params.be.next_pc = to; //LOK: This logic was changed to support ARM
  // since the lsb of the to address specifies whether the processor
  // is going to be in THUMB mode. This information would be lost
  // from DECAF_getPC(env);

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_END_CB], link) 
  {
    DEFENSIVE_CHECK0(cb_struct == NULL);

    // If it is a global callback or it is within the execution context,
    // invoke this callback
    if (cb_struct->to == INV_ADDR)
    {
      cb_struct->callback(&params);
    }
    else if ( (cb_struct->to & TARGET_PAGE_MASK) == (params.be.next_pc & TARGET_PAGE_MASK) )
    {
      if (cb_struct->from == INV_ADDR)
      {
        cb_struct->callback(&params);
      }
      else if ( (cb_struct->from & TARGET_PAGE_MASK) == (params.be.cur_pc & TARGET_PAGE_MASK) )
      {
        cb_struct->callback(&params);
      }
    }
  }
}

void helper_DECAF_invoke_insn_begin_callback(CPUState* env, gva_t pc)
{
  callback_struct_t *cb_struct;
  DECAF_Callback_Params params;

  DEFENSIVE_CHECK0(env == NULL);

  params.ib.env = env;
  params.ib.cur_pc = pc;

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_INSN_BEGIN_CB], link) 
  {
    DEFENSIVE_CHECK0(cb_struct == NULL);

    cb_struct->callback(&params);
  }
}

void helper_DECAF_invoke_insn_end_callback(CPUState* env, gva_t pc)
{
  callback_struct_t *cb_struct;
  DECAF_Callback_Params params;

  DEFENSIVE_CHECK0(env == NULL);

  params.ie.env = env;
  params.ie.cur_pc = pc;

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_INSN_END_CB], link) 
  {
    DEFENSIVE_CHECK0(cb_struct == NULL);

    cb_struct->callback(&params);
  }
}

void helper_DECAF_invoke_syscall_callback(CPUState* env, gva_t pc, target_ulong num)
{
  callback_struct_t *cb_struct = NULL;
  DECAF_Callback_Params params;

  DEFENSIVE_CHECK0(env == NULL);

  params.sc.env = env;
  params.sc.cur_pc = pc;
  params.sc.syscall_num = num;

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_SYSCALL_CB], link) 
  {
    DEFENSIVE_CHECK0(cb_struct == NULL);

    cb_struct->callback(&params);
  }
}

void DECAF_invoke_PGD_write_callback(CPUState* env, gpa_t oldpgd, gpa_t newpgd
#ifdef TARGET_ARM
, uint32_t c2base
#endif 
)
{
  callback_struct_t *cb_struct = NULL;
  DECAF_Callback_Params params;

  DEFENSIVE_CHECK0(env == NULL);

  params.pgd.env = env;
  params.pgd.curPGD = oldpgd;
  params.pgd.newPGD = newpgd;
#ifdef TARGET_ARM
  switch (c2base)
  {
    case (C2_BASE0):
    {
      params.pgd.c2_base = C2_BASE0;
      break;
    }
    case (C2_BASE1):
    {
      params.pgd.c2_base = C2_BASE1;
      break;
    }
    default:
    {
      return;
    }
  }
#endif

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_PGD_WRITE_CB], link) 
  {
    DEFENSIVE_CHECK0(cb_struct == NULL);

    cb_struct->callback(&params);
  }
}
void DECAF_callback_init(void)
{
  int i;

  for(i=0; i<DECAF_LAST_CB; i++)
  {
    LIST_INIT(&callback_list_heads[i]);
  }

  pOBBTable = CountingHashtable_new();
  pOBBPageTable = CountingHashtable_new();

  pOBEFromPageTable = CountingHashtable_new();
  pOBEToPageTable = CountingHashtable_new();
  pOBEPageMap = CountingHashmap_new();

  bEnableAllBlockBeginCallbacks = 0;
  enableAllBlockBeginCallbacksCount = 0;
  bEnableAllBlockEndCallbacks = 0;
  enableAllBlockEndCallbacksCount = 0;
}
