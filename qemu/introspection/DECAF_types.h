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

#ifndef DECAF_TYPES_H
#define DECAF_TYPES_H

#define DEFENSIVE_CHECK0(_bool) \
  do                            \
  {                             \
    if (_bool)                  \
    {                           \
      return;                   \
    }                           \
  }                             \
  while (0)                     

#define DEFENSIVE_CHECK1(_bool, _ret) \
  do                                  \
  {                                   \
    if (_bool)                        \
    {                                 \
      return (_ret);                  \
    }                                 \
  }                                   \
  while (0)                     

#define __STDC_LIMIT_MACROS // this header is sometimes called from C++
#include "qemu-common.h"

typedef target_ulong gva_t;
//Interestingly enough - target_phys_addr_t is defined as uint64 - what to do?
typedef target_ulong gpa_t;

typedef int gpid_t;

//to determine the HOST type - we use the definitions from TCG
// We use the same logic as defined in tcg.h
//typedef tcg_target_ulong hva_t;
//typedef tcg_target_ulong hpa_t;
#if UINTPTR_MAX == UINT32_MAX
  typedef uint32_t hva_t;
  typedef uint32_t hpa_t;
#elif UINTPTR_MAX == UINT64_MAX
  typedef uint64_t hva_t;
  typedef uint64_t hpa_t;
#else
  #error BLARB
#endif

typedef uintptr_t DECAF_Handle;
#define DECAF_NULL_HANDLE ((uintptr_t)NULL)

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
#endif
