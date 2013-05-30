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
 * SimpleCallback.c
 *
 *  Created on: Oct 16, 2012
 *      Author: lok
 */

#include "SimpleCallback.h"

SimpleCallback_t* SimpleCallback_new(void)
{
  SimpleCallback_t* pList = (SimpleCallback_t*) malloc(sizeof(SimpleCallback_t));
  if (pList == NULL)
  {
    return (NULL);
  }
  LIST_INIT(pList);
  return (pList);
}

DECAF_errno_t SimpleCallback_init(SimpleCallback_t* pList)
{
  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }
  LIST_INIT(pList);
  return (0);
}


DECAF_errno_t SimpleCallback_clear(SimpleCallback_t* pList)
{
  SimpleCallback_entry_t *cb_struct = NULL;

  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  while (!LIST_EMPTY(pList))
  {
    LIST_REMOVE(LIST_FIRST(pList), link);
    free(cb_struct);
  }

  return (0);
}

DECAF_errno_t SimpleCallback_delete(SimpleCallback_t* pList)
{
  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  SimpleCallback_clear(pList);

  free(pList);

  return (0);
}

//this is for backwards compatibility -
// for block begin and end - we make a call to the optimized versions
// for insn begin and end we just use the old logic
DECAF_Handle SimpleCallback_register(
    SimpleCallback_t* pList,
    SimpleCallback_func_t cb_func,
    int *cb_cond)
{
  if (pList == NULL)
  {
    return (DECAF_NULL_HANDLE);
  }

  SimpleCallback_entry_t* cb_struct = (SimpleCallback_entry_t*)malloc(sizeof(SimpleCallback_entry_t));
  if (cb_struct == NULL)
  {
    return (DECAF_NULL_HANDLE);
  }

  cb_struct->callback = cb_func;
  cb_struct->enabled = cb_cond;

  LIST_INSERT_HEAD(pList, cb_struct, link);

  return ((DECAF_Handle)cb_struct);
}

DECAF_errno_t SimpleCallback_unregister(SimpleCallback_t* pList, DECAF_Handle handle)
{
  SimpleCallback_entry_t *cb_struct = NULL;

  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, pList, link) {
    if((DECAF_Handle)cb_struct != handle)
      continue;

    LIST_REMOVE(cb_struct, link);
    free(cb_struct);

    return 0;
  }

  return (ITEM_NOT_FOUND_ERROR);
}

void SimpleCallback_dispatch(SimpleCallback_t* pList, void* params)
{
  SimpleCallback_entry_t *cb_struct;

  if (pList == NULL)
  {
    return ;
  }

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, pList, link) {
          // If it is a global callback or it is within the execution context,
          // invoke this callback
          if(!cb_struct->enabled || *cb_struct->enabled)
                  cb_struct->callback(params);
  }
}
