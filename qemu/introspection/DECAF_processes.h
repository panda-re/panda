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
 * This file was created to create a consistent interface for accessing 
 * guest process information. This is basically procmod.h in DECAF.
 * The difference is that the implementation is found in DroidScope's source
 * instead of procmod.cpp. That is DS replaces DECAF's procmod functionality
 * using its own implementation.
 *
 * @author Lok Yan
 * @date 31 DEC 2012
**/

#ifndef _DECAF_PROCESSES_H 
#define _DECAF_PROCESSES_H

#include "DECAF_shared/DECAF_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** When a new process entry is created. **/
typedef struct _CreateProc_Params
{
  gpid_t pid;
  union
  {
    gpa_t cr3;
    gpa_t pgd;
  };
}CreateProc_Params;
typedef void (*createproc_notify_t)(CreateProc_Params* params);

/** When the process entry is removed. **/
typedef struct _RemoveProc_Params
{
  gpid_t pid;
}RemoveProc_Params;
typedef void (*removeproc_notify_t)(RemoveProc_Params* params);

/** When a module is loaded **/
typedef struct _LoadModule_Params
{
  gpid_t pid;
  union
  {
    gpa_t cr3;
    gpa_t pgd;
  };
  char* name;
  gva_t base;
  gva_t size;
  char* full_name;
}LoadModule_Params;
typedef void (*loadmodule_notify_t)(LoadModule_Params* params);

typedef struct _ProcessUpdated_Params
{
  gpid_t pid;
  int mask;
}ProcessUpdated_Params;

typedef struct _ModulesUpdated_Params
{
  gpid_t pid;
  gva_t startAddr;
  int mask;
}ModulesUpdated_Params;

/** When the main module is loaded. A special case of LoadModule **/
typedef struct _LoadMainModule_Params
{
  gpid_t pid;
  union
  {
    gpa_t cr3;
    gpa_t pgd;
  };
  const char* name;
}LoadMainModule_Params;
typedef void (*loadmainmodule_notify_t)(LoadMainModule_Params* params);

typedef union _DECAF_Processes_Callback_Params
{
  CreateProc_Params cp;
  RemoveProc_Params rp;
  LoadModule_Params lm;
  LoadMainModule_Params lmm;
  ProcessUpdated_Params pu;
  ModulesUpdated_Params mu;
} DECAF_Processes_Callback_Params;

typedef enum {
  DECAF_PROCESSES_CREATE_PROCESS_CB = 0,
  DECAF_PROCESSES_REMOVE_PROCESS_CB,
  DECAF_PROCESSES_PROCESS_END_CB = DECAF_PROCESSES_REMOVE_PROCESS_CB, //alias
  DECAF_PROCESSES_LOAD_MODULE_CB,
  DECAF_PROCESSES_LOAD_MAIN_MODULE_CB,
  DECAF_PROCESSES_PROCESS_BEGIN_CB = DECAF_PROCESSES_LOAD_MAIN_MODULE_CB, //alias
  DECAF_PROCESSES_PROCESS_UPDATED_CB, //for example when the name has changed 
  DECAF_PROCESSES_MODULES_UPDATED_CB, //for example when something is remapped
  // NOT YET IMPLEMENTED
  DECAF_PROCESSES_LAST_CB, //place holder for the last position, no other uses.
} DECAF_Processes_callback_type_t;

typedef void (*DECAF_Processes_callback_func_t) (DECAF_Processes_Callback_Params* params);

DECAF_Handle DECAF_Processes_register_callback(
                DECAF_Processes_callback_type_t cb_type,
                DECAF_Processes_callback_func_t cb_func,
                int *cb_cond
                );

DECAF_errno_t DECAF_Processes_unregister_callback(DECAF_Processes_callback_type_t cb_type, DECAF_Handle handle);

#ifdef __cplusplus 
};
#endif

#endif

