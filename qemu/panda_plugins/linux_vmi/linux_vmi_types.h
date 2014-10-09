/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

/* Type definitions for introspecting into a Linux guest.
 * 
 */

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
 * DECAF_types.h
 * Some defines for commonly used types
 * @author: Lok Yan
 * @date: 19 SEP 2012
*/

#ifndef LINUX_VMI_TYPES_H
#define LINUX_VMI_TYPES_H

#define __STDC_LIMIT_MACROS // this header is sometimes called from C++
#include "qemu-common.h" //includes stdint.h

// Physical memory address
typedef target_phys_addr_t gpa_t;
// Virtual memory address
typedef target_ulong gva_t;
// Page directory base/ASID value. Note that eg on i386/PAE this is not the same as guest physical address
typedef target_ulong target_asid_t;

typedef int32_t gpid_t; // Linux PID is defined as signed 32-bit. see /usr/include/bits/typesizes.h

//Used for addresses since -1 is a rarely used-if ever 32-bit address
#define INV_ADDR (-1) //0xFFFFFFFF is only for 32-bit

/**
 * ERRORCODES
 */

typedef int DECAF_errno_t;
/**
 * Returned when a pointer is NULL when it should not have been
 */
#define NULL_POINTER_ERROR (-101)

/**
 * Returned when a pointer already points to something, although the function is expected to malloc a new area of memory.
 * This is used to signify that there is a potential for a memory leak.
 */
#define NON_NULL_POINTER_ERROR (-102)

/**
 * Returned when malloc fails. Out of memory.
 */
#define OOM_ERROR (-103)

/**
 * Returned when there is an error reading memory - for the guest.
 */
#define MEM_READ_ERROR (-104)

#define FILE_OPEN_ERROR (-105)
#define FILE_READ_ERROR (-105)
#define FILE_WRITE_ERROR (-105)

/**
 * Returned by functions that needed to search for an item before it can continue, but couldn't find it.
 */
#define ITEM_NOT_FOUND_ERROR (-106)

/**
 * Returned when one of the parameters into the function doesn't check out.
 */
#define PARAMETER_ERROR (-107)

#define UNINITIALIZED_ERROR (-108)

/**
 * A node in the module list
 */
typedef struct _ModuleNode
{
  gva_t startAddr;
  gva_t endAddr;
  gva_t flags;
  void* moduleInfo; //I used a void* on purpose so you can't access the module info directly
  struct _ModuleNode* next;
} ModuleNode;

/**
 * Maximum length of the arg[0] name in the shadow list
 */
#define MAX_PROCESS_INFO_NAME_LEN 128
/**
 * Maximum length of the comm name inside the task_struct
 */
#define MAX_TASK_COMM_LEN 16

/**
 * A smaller data structure (compared to the one below) for
 * threads
 */

typedef struct _ThreadNode
{
  union
  {
    gpid_t pid;
    gpid_t tid;
  };
  gva_t threadInfo;
  struct _ThreadNode* next;
} ThreadNode;

/**
 * A node in the shadow process (task really) list. 
 */
typedef struct _ProcessInfo
{
  gva_t task_struct;
  gpid_t pid;
  gpid_t parentPid;
  gpid_t tgid;
  gpid_t glpid;
  target_ulong uid;
  target_ulong gid;
  target_ulong euid;
  target_ulong egid;
  gpa_t pgd;
  char strName[MAX_PROCESS_INFO_NAME_LEN];
  char strComm[MAX_TASK_COMM_LEN];
  ModuleNode* modules;
  ThreadNode* threads;
} ProcessInfo;

#endif
