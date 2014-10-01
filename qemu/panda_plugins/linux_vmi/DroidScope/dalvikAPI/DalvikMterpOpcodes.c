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
 * DalvikMterpOpcodes.c
 *
 *  Created on: Sep 29, 2011
 *      Author: lok
 */


#include "DECAF_shared/DECAF_types.h"
#include "DECAF_shared/utils/OutputWrapper.h"
#include "DECAF_shared/utils/HashtableWrapper.h"
#include "DECAF_callback.h"
#include "DalvikAPI.h"
#include "dalvikAPI/DalvikOpcodeTable.h"

/************************************************************************
 * Start of implementation section for "Callbacks"
 ************************************************************************/

#include "DECAF_shared/utils/SimpleCallback.h"
#include "DS_utils/RangeList.h"

static SimpleCallback_t DS_Mterp_callbacks[DS_DALVIK_LAST_CB];

DECAF_Handle DS_Dalvik_register_callback(DS_Dalvik_callback_type_t cb_type, DS_Dalvik_callback_func_t cb_func, int* cb_cond)
{
  if ( (cb_type > DS_DALVIK_LAST_CB) || (cb_type < 0) )
  {
    return (DECAF_NULL_HANDLE);
  }
  return (SimpleCallback_register(&DS_Mterp_callbacks[cb_type], (SimpleCallback_func_t)cb_func, cb_cond)); 
}

DECAF_errno_t DS_Dalvik_unregister_callback(DS_Dalvik_callback_type_t cb_type, DECAF_Handle handle)
{
  if ( (cb_type > DS_DALVIK_LAST_CB) || (cb_type < 0) )
  {
    return (-1);
  }
  return (SimpleCallback_unregister(&DS_Mterp_callbacks[cb_type], handle));
}



//These are functions that are used to generate the DALVIK opcodes
//According to the specification, r8, or rBase is the base register for the mterp opcodes
// there are multiple ways that we can get this:
//1. Grab it from libdvm -- if the symbol is there dvmAsmInstructionStart //2. Grab it dynamically by figuring out when a dalvik instruction runs and then read r8 //3. Grab it from memory 
//The easiest is 1. by far, which only requires access to the symbol server which is what we will do

#define MTERP_USE_OPTIMIZED_BB

#ifdef MTERP_USE_OPTIMIZED_BB
//Defined inside the mterpinfo data structure
#else
static DECAF_Handle mterpHandle;
#endif


//we define the handle count as 256 << 6 (256 opcodes multiplied by 6)
// divided by the number of target pages there are
// we add 1 since the asmInstructionStart might not start on a page
// boundary. 
#define MTERP_HANDLE_COUNT ( ( (256 << 6) / TARGET_PAGE_SIZE ) + 1 )

typedef struct _MterpInfo
{
  gpid_t pid;
  gva_t iBase;
  RangeNode* ranges;
#ifdef MTERP_USE_OPTIMIZED_BB
  DECAF_Handle mterpHandles[MTERP_HANDLE_COUNT];
#endif
} MterpInfo;
 
//mterpMap will map PIDs to MterpInfos 
//TODO: Make a new hashmap for PIDs? This works as long as target_ulong is > than pid in size
static OpaqueHashmap* mterpMap = NULL;

void mterpBBCallback(CPUState *env, TranslationBlock *tb)
{
  if ( (mterpMap == NULL) || (env == NULL) )
  {
    return;
  }

  Dalvik_Callback_Params dalvikparams;

  MterpInfo* pInfo = NULL;
  if (OpaqueHashmap_getVal(mterpMap, getCurrentPID(), (void**)&pInfo) != 0)
  {
    return;
  }

  //check to make sure that the BB is for the right iBaseRange first
  uint32_t opcode = mterpAddrToOpcode(pInfo->iBase, tb->pc);
  if (opcode != INV_ADDR)
  {
    if (RangeList_exist(pInfo->ranges, getDalvikPC(env)))
    {
      dalvikparams.ib.env = env;
      dalvikparams.ib.dalvik_pc = getDalvikPC(env);
      dalvikparams.ib.opcode = opcode;
      SimpleCallback_dispatch(&DS_Mterp_callbacks[DS_DALVIK_INSN_BEGIN_CB], &dalvikparams);
    }
  }
}


inline DECAF_errno_t mterp_initIBase(gpid_t pid, gva_t iBase)
{
  if (mterpMap == NULL)
  {
    return (UNINITIALIZED_ERROR);
  }

  if (!OpaqueHashmap_exist(mterpMap, pid))
  {
    MterpInfo* pInfo = (MterpInfo*)malloc(sizeof(MterpInfo)); 
    if (pInfo == NULL)
    {
      return (OOM_ERROR);
    }

    pInfo->pid = pid;
    pInfo->iBase = iBase;
    pInfo->ranges = NULL;

  #ifdef MTERP_USE_OPTIMIZED_BB 
    int i = 0;
    for (i = 0; i < MTERP_HANDLE_COUNT; i++)
    {
      pInfo->mterpHandles[i] = DECAF_registerOptimizedBlockBeginCallback(&mterpBBCallback, iBase + (TARGET_PAGE_SIZE * i), OCB_PAGE);
      if (pInfo->mterpHandles[i] == DECAF_NULL_HANDLE)
      {
        free(pInfo);
        return (-1);
      }
    }
  #endif
 
    OpaqueHashmap_add(mterpMap, pid, pInfo);
  }

  return (0);
}

DECAF_errno_t mterp_clear(gpid_t pid)
{
  if (mterpMap == NULL)
  {
    return (UNINITIALIZED_ERROR);
  }

  MterpInfo* pInfo = NULL;

  if (OpaqueHashmap_getVal(mterpMap, pid, (void**)&pInfo) != 0)
  {
    return (ITEM_NOT_FOUND_ERROR);
  }
 
  if (pInfo->ranges != NULL)
  {
    RangeList_free(pInfo->ranges);
    pInfo->ranges = NULL;
  }

  #ifdef MTERP_USE_OPTIMIZED_BB
  int i = 0;
  for (i = 0; i < MTERP_HANDLE_COUNT; i++)
  {
    if (pInfo->mterpHandles[i] != DECAF_NULL_HANDLE)
    {
      DECAF_unregisterOptimizedBlockBeginCallback(pInfo->mterpHandles[i]);
      pInfo->mterpHandles[i] = DECAF_NULL_HANDLE;
    }
  }
  #endif
  OpaqueHashmap_remove(mterpMap, pid);

  //now free the mterpInfo 
  free(pInfo);

  return (0);
}

inline DECAF_errno_t addMterpOpcodesRange(gpid_t pid, gva_t startAddr, gva_t endAddr)
{
  if (mterpMap == NULL)
  {
    return (UNINITIALIZED_ERROR);
  }

  MterpInfo* pInfo = NULL;

  if (OpaqueHashmap_getVal(mterpMap, pid, (void**)&pInfo) != 0)
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

inline DECAF_errno_t removeMterpOpcodesRange(gpid_t pid, gva_t startAddr, gva_t endAddr)
{
  if (mterpMap == NULL)
  {
    return (UNINITIALIZED_ERROR);
  }

  MterpInfo* pInfo = NULL;

  if (OpaqueHashmap_getVal(mterpMap, pid, (void**)&pInfo) != 0)
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

int mterpBBCondFunc(DECAF_callback_type_t cbType, gva_t curPC, gva_t nextPC)
{
  DEFENSIVE_CHECK1(cbType != DECAF_BLOCK_BEGIN_CB, 0);
  
  if (mterpMap == NULL)
  {
    return (0);
  }

  MterpInfo* pInfo = NULL;

  if (OpaqueHashmap_getVal(mterpMap, getCurrentPID(), (void**)&pInfo) != 0)
  {
    return (0);
  }

  if ( (curPC  >= pInfo->iBase) && (curPC <= (pInfo->iBase + (256 << 6))) )
  {
    return (1);
  }

  return (0);
}


/*************
 * Init and close functions
 ************/

void DalvikMterpOpcodes_init()
{
  //we use mterpMap as the initialized indicator
  if (mterpMap != NULL)
  {
    return;
  }

  //get a new mtermap
  mterpMap = OpaqueHashmap_new();

  //initialize the callbacks
  size_t i = 0;
  for (i = 0; i < DS_DALVIK_LAST_CB; i++)
  {
    SimpleCallback_init(&DS_Mterp_callbacks[i]);
  }
  //register the BB callback
#ifdef MTERP_USE_OPTIMIZED_BB
  //nothing to do here
#else
  mterpHandle = DECAF_register_callback(NULL, PANDA_CB_BEFORE_BLOCK_EXEC, mterpBBCallback);
  //flush the cache
  DECAF_flushTranslationCache();
#endif
}

void DalvikMterpOpcodes_close()
{
 
#ifdef MTERP_USE_OPTIMIZED_BB
   
#else
  DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, mterpHandle);
#endif

  target_ulong key;
  void* val;
  MterpInfo* pInfo;

  if (mterpMap != NULL)
  {
    while (OpaqueHashmap_getFront(mterpMap, &key, &val) == 0)
    {
      pInfo = (MterpInfo*)val;
      RangeList_free(pInfo->ranges);
       
      #ifdef MTERP_USE_OPTIMIZED_BB
      int i = 0;
      for (i = 0; i < MTERP_HANDLE_COUNT; i++)
      {
        if (pInfo->mterpHandles[i] != DECAF_NULL_HANDLE)
        {
          DECAF_unregisterOptimizedBlockBeginCallback(pInfo->mterpHandles[i]);
          pInfo->mterpHandles[i] = DECAF_NULL_HANDLE;
        }
      }
      #endif

      OpaqueHashmap_removeFront(mterpMap);
      free(pInfo);
    }
  }

  OpaqueHashmap_free(mterpMap);
  mterpMap = NULL;
}
