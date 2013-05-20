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
 * SimpleCallback.h
 *
 *  Created on: Oct 16, 2012
 *      Author: lok
 *  The idea behind this file is to create a simple data structure for
 *  maintaining a simple callback interface. In this way the core developers
 *  can expose their own callbacks. For example, procmod can now expose
 *  callbacks for loadmodule instead of having the plugin directly set the
 *  single loadmodule_notifier inside procmod, which is messy
 */

#ifndef SIMPLECALLBACK_H_
#define SIMPLECALLBACK_H_

#include <sys/queue.h>
#include "introspection/DECAF_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*SimpleCallback_func_t) (void* params);

typedef struct SimpleCallback_entry{
        int *enabled;
        SimpleCallback_func_t callback;
        LIST_ENTRY(SimpleCallback_entry) link;
}SimpleCallback_entry_t;

typedef LIST_HEAD(SimpleCallback_list_head, SimpleCallback_entry) SimpleCallback_t;

/** 
 * Register a new callback
 * @param pList pointer to the SimpleCallback list
 * @param cb_func the callback function to invoke
 * @param cb_cond Enabled or not? NULL means alwyas enabled
 * @return Handle to the newly registered callback
**/
DECAF_Handle SimpleCallback_register(
    SimpleCallback_t* pList,
    SimpleCallback_func_t cb_func,
    int *cb_cond);

/**
 * Unregister a callback
 * @param pList Pointer to the list
 * @param handle The handle to unregister
 * @return 0 if successful
**/
DECAF_errno_t SimpleCallback_unregister(SimpleCallback_t* pList, DECAF_Handle handle);

/**
 * Returns a pointer to a new SimpleCallback list - paired with delete
*/
SimpleCallback_t* SimpleCallback_new(void);

/**
 * Deletes the whole callback list including the node pointed to by pList
 * This is done by first clearing the list and then freeing the pList LIST_HEAD. 
 * NOTE: The caller SHOULD NOT USE pList after this call without another new!!!!
 * @param pList the pointer to the list
**/
DECAF_errno_t SimpleCallback_delete(SimpleCallback_t* pList);

/**
 * Initializes the callbacklist pointed to by pList
 * @param pList Pointer to the SimpleCallback list
**/
DECAF_errno_t SimpleCallback_init(SimpleCallback_t* pList);

/**
 * Clears the whole list. Clearing means frees all memory allocated for
 * the nodes in this list. The LIST_HEAD pointed to by pList is untouched!
**/ 
DECAF_errno_t SimpleCallback_clear(SimpleCallback_t* pList);

/**
 * Iterates through the SimpleCallback list and invokes the registered
 * callback functions with param.
**/
void SimpleCallback_dispatch(SimpleCallback_t* pList, void* params);

#ifdef __cplusplus
}
#endif

#endif /* SIMPLECALLBACK_H_ */
