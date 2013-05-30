/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
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
 * RangeList.h
 *
 *  Created on: Jan 5, 2012
 *      Author: lok
 */

#ifndef RANGE_LIST_H
#define RANGE_LIST_H

#include "introspection/utils/OutputWrapper.h"
#include "introspection/DECAF_types.h"

#ifndef RANGE_TYPE
#define RANGE_TYPE target_ulong 
#endif

typedef struct _TheRange
{
  RANGE_TYPE start;
  RANGE_TYPE end; //NON INCLUSIVE
} TheRange;

typedef struct _RangeNode
{
  TheRange range;
  struct _RangeNode* next;
}RangeNode;

static inline RangeNode* RangeList_new(RANGE_TYPE start, RANGE_TYPE end)
{
  RangeNode* temp = (RangeNode*)(malloc(sizeof(RangeNode)));
  if (temp != NULL)
  {
    temp->range.start = start;
    temp->range.end = end;
    temp->next = NULL;
  }

  return (temp);
}

static inline void RangeList_free(RangeNode* pList)
{
  RangeNode* i = pList;
  RangeNode* temp = NULL;
  while (i != NULL)
  {
    temp = i;
    i = i->next;
    free(temp);
  }
}

static inline RangeNode* RangeList_find(RangeNode* pList, RANGE_TYPE val)
{
  RangeNode* i = pList;
  while (i != NULL)
  {
    if ( (val >= i->range.start) && (val < i->range.end) )
    {
      return (i);
    }
    i = i->next;
  }
  return (NULL);
}

static inline int RangeList_exist(RangeNode* pList, RANGE_TYPE val)
{
  return (RangeList_find(pList, val) != NULL);
}

static inline DECAF_errno_t RangeList_pushFront(RangeNode* pList, RANGE_TYPE start, RANGE_TYPE end)
{
  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  RangeNode* temp = NULL;
  temp = RangeList_new(pList->range.start, pList->range.end);
  if (temp == NULL)
  {
    return (OOM_ERROR);
  }
  //since we are here, lets just move things along
  temp->next = pList->next;
  pList->next = temp;
  pList->range.start = start;
  pList->range.end = end;
  return (0);
}



static inline DECAF_errno_t RangeList_insertAfter(RangeNode* pList, RANGE_TYPE start, RANGE_TYPE end)
{
  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  RangeNode* temp = RangeList_new(start, end);
  temp->next = pList->next;
  pList->next = temp;
  return (0);
}

static inline void RangeList_print(FILE* fp, RangeNode* pList)
{
  RangeNode* i = pList;
  while (i != NULL)
  {
    DECAF_fprintf(fp, "%x -> %x\n", i->range.start, i->range.end);
    i = i->next;
  }
}

DECAF_errno_t RangeList_add(RangeNode* pList, RANGE_TYPE start, RANGE_TYPE end);

/**
 * Removes an entry (or actually a range) from the range list
 * @return negative error values
 * @return 0 If successful
 * @return 1 If successful AND the user should free the list
**/
int RangeList_remove(RangeNode* pList, RANGE_TYPE start, RANGE_TYPE end);

DECAF_errno_t RangeList_checkAndMerge(RangeNode* pList);

#define RANGELIST_FOR_EACH(_rangeNode, _i) \
  for (_i = _rangeNode; _i != NULL; _i = _i->next)

#endif//RANGE_LSIT_H
