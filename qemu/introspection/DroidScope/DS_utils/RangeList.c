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
 * RangeList.c
 *
 *  Created on: Jan 5, 2012
 *      Author: lok
 */

#include "DS_utils/RangeList.h"

DECAF_errno_t RangeList_checkAndMerge(RangeNode* pList)
{
  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  while ( (pList->next != NULL) && (pList->range.end >= pList->next->range.start) )
  {
    RangeNode* temp = pList->next;
    if (pList->range.end <= pList->next->range.end)
    {
      pList->range.end = pList->next->range.end;
    }
    pList->next = pList->next->next;
    free(temp);
  }

  return (0);
}

DECAF_errno_t RangeList_add(RangeNode* pList, RANGE_TYPE start, RANGE_TYPE end)
{
  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  if (end < start)
  {
    return (PARAMETER_ERROR);
  }

  RangeNode* prev = NULL;
  RangeNode* i = pList;
  while (i != NULL)
  {
    //lets take care of the first case where we have to add it in the front!
    if ( end < i->range.start )
    {
      return (RangeList_pushFront(i, start, end));
    }

    //it can't go into the front, but perhaps we can integrate it with the first node
    // there are two cases
    // extended the range before
    if ( (end <= i->range.end) )
    {
      if (start < i->range.start)
      {
        i->range.start = start;
      }
      return (0);
    }

    // extend the range after
    if ( (start <= i->range.end) )
    {
      i->range.end = end;
      //now that we extended the range, we might need to merge with the next one
      return (RangeList_checkAndMerge(i));
    }

    prev = i;
    i = i->next;
  }

  //if we are here that means we couldn't find it, so lets just insert it at the end
  // which is what prev is pointing to prev can't be null by now since i is not NULL
  return (RangeList_insertAfter(prev, start, end));
}

int RangeList_remove(RangeNode* pList, RANGE_TYPE start, RANGE_TYPE end)
{
  if (pList == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  if (end < start)
  {
    return (PARAMETER_ERROR);
  }

  if (end <= pList->range.start)
  {
    //nothing to do here
    return (0);
  }

  RangeNode* prev = NULL;
  RangeNode* i = pList;
  while (i != NULL)
  {
    //there are a few cases that we have to handle in order of simplicity
    //First is that the range gets truncated at the beginning
    if ( (start <= i->range.start) && (end < i->range.end ) )
    {
      i->range.start = end;
      return (0);
    }
    //Second is that the removed range bisects the current range
    else if ( (start > i->range.start) && (end < i->range.end) )
    {
      RANGE_TYPE t = i->range.end;
      i->range.end = start;
      return (RangeList_insertAfter(i, end, t));
    }
    //third we truncate at the end
    else if ( (start > i->range.start) && (start < i->range.end) && (end >= i->range.end) )
    {
     //so what we do is we truncate the current and then recurse
     i->range.end = start;
     if (RangeList_remove(i->next, start, end) == 1)
     {
       free (i->next);
       i->next = NULL;
     }
     return (0);
    }
    //Finally we remove the whole range
    else if ( (start <= i->range.start) && (end >= i->range.end) )
    {
      //now here we have a couple of special cases as well
      //first is that this is the end of the list, what we do is to simply replace the start and end values with 0
      if (i->next == NULL)
      {
        i->range.start = 0;
        i->range.end = 0;
        return (1); //we return 1 to signify that this should also be freed, but we just can't do it
      }
      else //second is to shift the next node to the current one and then remove the next
      {
        i->range.start = i->next->range.start;
        i->range.end = i->next->range.end;
        RangeNode* temp = i->next;
        i->next = i->next->next;
        free (temp);

        //but that too can be affected by the range we are removing, thus recurse
        int ret = RangeList_remove(i, start, end);
        if (ret == 1)
        {
          //if it is 1, that means i should also be freed
          // so if there is a previous then free the current and update prev's next pointer
          if (prev != NULL)
          {
            prev->next = NULL;
            free (i);
            ret = 0;
          }
        }
        return (ret);
      }
    }

    prev = i;
    i = i->next;
  }

  //if we are here that means we couldn't find it, so nothing to do
  return (0);
}


