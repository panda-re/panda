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
 * DalvikContext.c
 *
 *  Created on: Dec 21, 2011
 *      Author: lok
 */


#include "DECAF_shared/DECAF_types.h"
#include "DECAF_shared/DECAF_callback.h"
//#include "DECAF_shared/DECAF_main.h"
#include "DECAF_shared/utils/HashtableWrapper.h"
#include "LinuxAPI.h"
#include "DalvikAPI.h"
#include "DS_utils/RangeList.h"

//static gva_t _getCodeAddr = DVM_JIT_GET_CODE_ADDR;
static gva_t _getCodeAddr = INV_ADDR;

typedef struct _DisableJitInfo
{
  gpid_t pid;
  gva_t getCodeAddr;
  RangeNode* ranges;
  DECAF_Handle handle;
  gva_t retAddr; 
  DECAF_Handle retHandle;
} DisableJitInfo;

//TODO: Same as in DalvikMterpOpcodes - create a new hashmap?
static OpaqueHashmap* disableJitMap = NULL;

void disableJitBBCallback(DECAF_Callback_Params* params)
{
  if ( (disableJitMap == NULL) || (params == NULL) )
  {
    return;
  }

  CPUState* env = params->bb.env;
  TranslationBlock* tb = params->bb.tb;
  Dalvik_Callback_Params dalvikparams;

  DEFENSIVE_CHECK0((env == NULL) || (tb == NULL));

  DisableJitInfo* pInfo = NULL;

  if (OpaqueHashmap_getVal(disableJitMap, getCurrentPID(), (void**)&pInfo) != 0)
  {
    return;
  }

  if (tb->pc == pInfo->getCodeAddr)
  {
    if (pInfo->retHandle != DECAF_NULL_HANDLE)
    {
      return;
    }

    if (RangeList_exist(pInfo->ranges, DECAF_getFirstParam(env)))
    {
      pInfo->retAddr = lp_strip(DECAF_getReturnAddr(env));
      pInfo->retHandle = DECAF_registerOptimizedBlockBeginCallback(&disableJitBBCallback, pInfo->retAddr, OCB_CONST);
    }

      /** TESTING SETTING THE TARGET ADDRESS TO 0 -- RESULTS: It doesn't make sense why the performance is so much lower
         than the original method of replacing the return value with 0. This is particularly true for the string tests
         in com.android.cm3 since most of the work is being done outside of the library. Also setting it to 0 makes
         gives in consistent results in the . and + in terms of the calls and returns. Before I made this change
         there seems to be two .s per + in linpack (which is weird in itself) but after this change there seems to be
         many .s per + like thousands more - it is just one single line change - perhaps it has something to do with
         the code itself where changing the address to 0 is NOT forcing a NULL to be returned**/
      //printf("%x\n", env->regs[0]);
      //env->regs[0] = 0;
      /** END TEST **/
  }
  else if ( (pInfo->retHandle != DECAF_NULL_HANDLE) && (lp_strip(tb->pc) == pInfo->retAddr) )
  {
#ifdef TARGET_ARM
    env->regs[0] = 0;
#elif defined(TARGET_I386)
    env->regs[R_EAX] = 0;
#endif
    
    DECAF_unregisterOptimizedBlockBeginCallback(pInfo->retHandle);
    pInfo->retHandle = DECAF_NULL_HANDLE;
    pInfo->retAddr = INV_ADDR;
    //printf("+");
  }
}

inline DECAF_errno_t disableJitInitGetCodeAddr(gpid_t pid, gva_t getCodeAddr)
{
  if (disableJitMap == NULL)
  {
    return (UNINITIALIZED_ERROR);
  }

  if (!OpaqueHashmap_exist(disableJitMap, pid))
  {
    DisableJitInfo* pInfo = (DisableJitInfo*)malloc(sizeof(DisableJitInfo)); 
    if (pInfo == NULL)
    {
      return (OOM_ERROR);
    }

    pInfo->pid = pid;
    pInfo->ranges = NULL;

    pInfo->retAddr = INV_ADDR;
    pInfo->retHandle = DECAF_NULL_HANDLE;

    pInfo->getCodeAddr = getCodeAddr;
    pInfo->handle = DECAF_registerOptimizedBlockBeginCallback(&disableJitBBCallback, getCodeAddr, OCB_PAGE);
    if (pInfo->handle == DECAF_NULL_HANDLE)
    {
      free(pInfo);
      return (-1);
    }
 
    OpaqueHashmap_add(disableJitMap, pid, pInfo);
  }

  return (0);
}


inline int addDisableJitRange(gpid_t pid, gva_t startAddr, gva_t endAddr)
{
  if (disableJitMap == NULL)
  {
    return (UNINITIALIZED_ERROR);
  }

  DisableJitInfo* pInfo = NULL;

  if (OpaqueHashmap_getVal(disableJitMap, pid, (void**)&pInfo) != 0)
  {
    return (ITEM_NOT_FOUND_ERROR);
  }
 
  if (pInfo == NULL)
  {
    //does not exist!!
    return (ITEM_NOT_FOUND_ERROR);
  }

  if (pInfo->ranges == NULL)
  {
    pInfo->ranges = RangeList_new(startAddr, endAddr);
    if (pInfo->ranges == NULL)
    {
      free(pInfo);
      return (OOM_ERROR);
    }
    return (0);
  }

  return (RangeList_add(pInfo->ranges, startAddr, endAddr));
  
}

inline int removeDisableJitRange(gpid_t pid, gva_t startAddr, gva_t endAddr)
{
  if (disableJitMap == NULL)
  {
    return (UNINITIALIZED_ERROR);
  }

  DisableJitInfo* pInfo = NULL;

  if (OpaqueHashmap_getVal(disableJitMap, pid, (void**)&pInfo) != 0)
  {
    return (ITEM_NOT_FOUND_ERROR);
  }
 
  if (pInfo->ranges == NULL)
  {
    return (ITEM_NOT_FOUND_ERROR);
  }

  if (RangeList_remove(pInfo->ranges, startAddr, endAddr) == 1)
  {
    //we can also use RangeList_free...
    free(pInfo->ranges);
    pInfo->ranges = NULL;
  }

  return (0);
}

void DalvikDisableJit_init(gva_t getCodeAddr)
{
  if (disableJitMap != NULL)
  {
    return;
  }

  disableJitMap = OpaqueHashmap_new();
}

void DalvikDisableJit_close(void)
{
  target_ulong key;
  void* val;
  DisableJitInfo* pInfo;

  if (disableJitMap != NULL)
  {
    while (OpaqueHashmap_getFront(disableJitMap, &key, &val) == 0)
    {
      pInfo = (DisableJitInfo*)val;
      RangeList_free(pInfo->ranges);
       
      #ifdef MTERP_USE_OPTIMIZED_BB
      if (pInfo->handle != DECAF_NULL_HANDLE)
      {
        DECAF_unregisterOptimizedBlockBeginCallback(pInfo->handle);
        pInfo->handle = DECAF_NULL_HANDLE;
      }
      if (pInfo->retHandle != DECAF_NULL_HANDLE)
      {
        DECAF_unregisterOptimizedBlockBeginCallback(pInfo->retHandle);
        pInfo->retHandle = DECAF_NULL_HANDLE;
      }
      #endif

      OpaqueHashmap_removeFront(disableJitMap);
      free(pInfo);
    }
  }

  OpaqueHashmap_free(disableJitMap);
  disableJitMap = NULL;
}


