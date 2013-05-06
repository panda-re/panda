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
 * DECAF_callback.h
 *
 *  Created on: Apr 10, 2012
 *      Author: heyin@syr.edu
 */

#ifndef DECAF_CALLBACK_H_
#define DECAF_CALLBACK_H_

//LOK: for CPUState
// #include "cpu.h" //Not needed - included in DECAF_callback_common.h
// #include "DECAF_shared/DECAF_types.h" // not needed either
#include "DECAF_shared/DECAF_callback_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/// \brief Register a callback function
///
/// @param cb_type the event type
/// @param cb_func the callback function
/// @param cb_cond a pointer to a function that is used for user-defined
///   callback event determination. For example, when registering for
///   the block begin callback type where cb_cond_func is not NULL then
///   whenever a block is translated cb_cond_func will be called and
///   at the beginning of every basic block cb_func will be called. If
///   it is NULL then it is assumed that cb_cond_func always returns TRUE
/// @return handle, which is needed to unregister this callback later.
extern DECAF_Handle DECAF_register_callback(
		DECAF_callback_type_t cb_type,
		DECAF_callback_func_t cb_func,
		DECAF_cond_func_t cb_cond_func
                );

extern DECAF_errno_t DECAF_unregister_callback(DECAF_callback_type_t cb_type, DECAF_Handle handle);

/**
 * Register a new optimized block begin callback. 
 * As implemented now, registering OCB_ALL would increment a counter. Removing OCB_ALL would decrement a counter - to 0.
 *   This is done to ensure that if A and B both register for OCB_ALL, and then A removes its callback, B will continue
 *   to get its requested callbacks.
 * @param addr The condition
 * @param type The condition type
 *
 */
DECAF_Handle DECAF_registerOptimizedBlockBeginCallback(
    DECAF_callback_func_t cb_func,
    gva_t addr,
    OCB_t type);

/**
 * Register a new optimized block end callback. A callback will be generated when the current basic block
 * begins at the same page as FROM and the target address is on the same page as TO. Either of these can
 * be INV_ADDR which equates to a don't care. If both are INV_ADDR then it is the same as enabling
 * ALL block end conditions. Similar to the block begin callback conditions, a counter is used for the ALL
 * condition
 * @param from The from page
 * @param to The to page
 */

DECAF_Handle DECAF_registerOptimizedBlockEndCallback(
    DECAF_callback_func_t cb_func,
    gva_t from,
    gva_t to);

DECAF_errno_t DECAF_unregisterOptimizedBlockBeginCallback(DECAF_Handle handle);

DECAF_errno_t DECAF_unregisterOptimizedBlockEndCallback(DECAF_Handle handle);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif /* DECAF_CALLBACK_H_ */
