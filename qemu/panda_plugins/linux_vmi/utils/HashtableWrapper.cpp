/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
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
 * HashtableWrapper.cpp
 *
 *  Created on: Dec 21, 2011
 *      Author: lok
 */

#include "DECAF_types.h"
#include "HashtableWrapper.h"
#include "OutputWrapper.h"

#include <tr1/unordered_set>

using namespace std::tr1;

typedef unordered_set<target_ulong> uset;

Hashtable* Hashtable_new()
{
  uset* pTable = new uset();
  return ( (Hashtable*)pTable );
}

void Hashtable_free(Hashtable* pTable)
{
  if (pTable != NULL)
  {
    delete( (uset*)pTable );
  }
}

int Hashtable_add(Hashtable* pHash, target_ulong item)
{
  uset* pTable = (uset*) pHash;
  if (pTable == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  std::pair<uset::iterator, bool> ret = pTable->insert(item);
  if (ret.second)
  {
    #ifdef DECAF_DEBUG_VERBOSE
    DECAF_printf("Adding [%x]\n", item);
    #endif
    return (1);
  }
  return (0);
}

int Hashtable_remove(Hashtable* pHash, target_ulong item)
{
  uset* pTable = (uset*) pHash;
  if (pTable == NULL)
  {
    return (NULL_POINTER_ERROR);
  }
  #ifdef DECAF_DEBUG_VERBOSE
  DECAF_printf("Removing [%x]\n", item);
  #endif
  pTable->erase(item);
  return (1);
}

int Hashtable_exist(Hashtable* pHash, target_ulong item)
{ uset* pTable = (uset*) pHash;
  if (pTable == NULL)
  {
    return (0);
  }
  return ( (pTable->find(item)) != pTable->end() );
}

void Hashtable_print(FILE* fp, Hashtable* pHash)
{
  uset* pTable = (uset*)pHash;
  if (pTable == NULL)
  {
    return;
  }

  for (uset::const_iterator it = pTable->begin(); it != pTable->end(); it++)
  {
    DECAF_fprintf(fp, "    %x\n", *it);
  }
}

#include <tr1/unordered_map>

typedef unordered_map<target_ulong, size_t> cset;

CountingHashtable* CountingHashtable_new()
{
  return ( (CountingHashtable*)(new cset()));
}

void CountingHashtable_free(CountingHashtable* pTable)
{
  if (pTable != NULL)
  {
    delete ( (cset*)pTable );
  }
}

size_t CountingHashtable_add(CountingHashtable* pTable, target_ulong key)
{
  if (pTable == NULL)
  {
    return (0);
  }

  cset* pTemp = (cset*)pTable;

  //here I assume that accessing size is quicker than searching to
  // determine if the key exists - NOT THREAD SAFE
  size_t prevSize = pTemp->size();

  //get the reference to the value
  size_t& val = (*pTemp)[key];
  //increment it
  val++;
  //if we just increased the size (this means that this is a new key)
  // then reset the value to 1 - I do this because int is not
  // initialized to 0 by default
  if (pTemp->size() > prevSize)
  {
    val = 1;
  }

  return (val);
}

size_t CountingHashtable_remove(CountingHashtable* pTable, target_ulong key)
{
  //just going to use the [] operator, which happens to create a new hashtable
  // if its not there already - might change this later
  //Very similar to the add case, except we reset the size_t to 0
  cset* pTemp = (cset*)pTable;
  if (pTemp == NULL)
  {
    return (0);
  }

  size_t prevSize = pTemp->size();
  size_t& val = (*pTemp)[key];
  val--;
  if (pTemp->size() > prevSize)
  {
    val = 0;
  }

  return (val);
}


int CountingHashtable_exist(CountingHashtable* pTable, target_ulong key)
{
  if (pTable == NULL)
  {
    return (0);
  }

  cset* pTemp = (cset*)pTable;
  cset::const_iterator it = pTemp->find(key);
  if (it == pTemp->end())
  {
    return (0);
  }

  return (it->second > 0);
}

size_t CountingHashtable_count(CountingHashtable* pTable, target_ulong key)
{
  if (pTable == NULL)
  {
    return (0);
  }

  cset* pTemp = (cset*)pTable;
  cset::const_iterator it = pTemp->find(key);
  if (it == pTemp->end())
  {
    return (0);
  }

  return (it->second);
}

void CountingHashtable_print(FILE* fp, CountingHashtable* pTable)
{
  cset* pTemp = (cset*)pTable;

  if (pTemp == NULL)
  {
    return;
  }

  for (cset::const_iterator it = pTemp->begin(); it != pTemp->end(); it++)
  {
    if (it->second > 0)
    {
      DECAF_fprintf(fp, "  %x [%u] ->\n", it->first, it->second);
    }
  }
}

typedef unordered_map<target_ulong, uset> umap;

Hashmap* Hashmap_new()
{
  return ( (Hashmap*)(new umap()));
}

void Hashmap_free(Hashmap* pMap)
{
  if (pMap != NULL)
  {
    delete ( (umap*)pMap );
  }
}

int Hashmap_add(Hashmap* pMap, target_ulong key, target_ulong val)
{
  umap* pUmap = (umap*)pMap;
  if (pUmap == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  std::pair<uset::iterator, bool> ret = (*pUmap)[key].insert(val);
  if (ret.second)
  {
    return (1);
  }

  return (0);
}

int Hashmap_remove(Hashmap* pMap, target_ulong key, target_ulong val)
{
  //just going to use the [] operator, which happens to create a new hashtable
  // if its not there already - might change this later
  umap* pUmap = (umap*)pMap;
  if (pUmap == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  (*pUmap)[key].erase(val);
  return (1);
}


Hashtable* Hashmap_getHashtable(Hashmap* pMap, target_ulong key)
{
  umap* pUmap = (umap*)pMap;
  if (pUmap == NULL)
  {
    return (NULL);
  }

  umap::iterator it = pUmap->find(key);
  if (it == pUmap->end())
  {
    return (NULL);
  }

  return ((Hashtable*)(&(it->second)));
}

int Hashmap_exist(Hashmap* pMap, target_ulong from, target_ulong to)
{
  Hashtable* pTable = Hashmap_getHashtable(pMap, from);

  if (pTable == NULL)
  {
    return (0);
  }

  return (Hashtable_exist(pTable, to));
}

void Hashmap_print(FILE* fp, Hashmap* pMap)
{
  umap* pUmap = (umap*)pMap;

  if (pUmap == NULL)
  {
    return;
  }

  for (umap::const_iterator it = pUmap->begin(); it != pUmap->end(); it++)
  {
    DECAF_fprintf(fp, "  %x ->\n", it->first);
    Hashtable_print(fp, (Hashtable*)(&(it->second)));
  }
}

typedef unordered_map<target_ulong, cset> cmap;

CountingHashmap* CountingHashmap_new()
{
  return ( (CountingHashmap*)(new cmap()));
}

void CountingHashmap_free(CountingHashmap* pMap)
{
  if (pMap != NULL)
  {
    delete ( (cmap*)pMap );
  }
}

size_t CountingHashmap_add(CountingHashmap* pMap, target_ulong key, target_ulong val)
{
  cmap* pCmap = (cmap*)pMap;
  if (pCmap == NULL)
  {
    return (0);
  }

  return (CountingHashtable_add((CountingHashtable*)(&(*pCmap)[key]), val));
}

size_t CountingHashmap_remove(CountingHashmap* pMap, target_ulong key, target_ulong val)
{
  cmap* pCmap = (cmap*)pMap;
  if (pCmap == NULL)
  {
    return (0);
  }

  return (CountingHashtable_remove((CountingHashtable*)(&(*pCmap)[key]), val));
}

CountingHashtable* CountingHashmap_getCountingHashtable(CountingHashmap* pMap, target_ulong key)
{
  cmap* pCmap = (cmap*)pMap;
  if (pCmap == NULL)
  {
    return (NULL);
  }

  cmap::iterator it = pCmap->find(key);
  if (it == pCmap->end())
  {
    return (NULL);
  }

  return ((CountingHashtable*)(&(it->second)));
}

int CountingHashmap_exist(CountingHashmap* pMap, target_ulong from, target_ulong to)
{
  CountingHashtable* pTable = CountingHashmap_getCountingHashtable(pMap, from);

  if (pTable == NULL)
  {
    return (0);
  }

  return (CountingHashtable_exist(pTable, to));
}

size_t CountingHashmap_count(CountingHashmap* pMap, target_ulong key, target_ulong val)
{
  cmap* pCmap = (cmap*)pMap;
  if (pCmap == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  return (CountingHashtable_count((CountingHashtable*)(&(*pCmap)[key]), val));
}

void CountingHashmap_print(FILE* fp, CountingHashmap* pMap)
{
  cmap* pCmap = (cmap*)pMap;

  if (pCmap == NULL)
  {
    return;
  }

  for (cmap::const_iterator it = pCmap->begin(); it != pCmap->end(); it++)
  {
    DECAF_fprintf(fp, "  %x ->\n", it->first);
    CountingHashtable_print(fp, (CountingHashtable*)(&(it->second)));
  }
}


typedef unordered_map<target_ulong, void*> ohmap;

OpaqueHashmap* OpaqueHashmap_new(void)
{
  return ( (OpaqueHashmap*)(new ohmap()));
}

void OpaqueHashmap_free(OpaqueHashmap* pMap)
{
  if (pMap != NULL)
  {
    delete ( (ohmap*)pMap );
  }
}

DECAF_errno_t OpaqueHashmap_add(OpaqueHashmap* pMap, target_ulong key, void* val)
{
  if (pMap == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  ohmap* pTemp = (ohmap*)pMap;

  (*pTemp)[key] = val;

  return (0);
}

DECAF_errno_t OpaqueHashmap_remove(OpaqueHashmap* pMap, target_ulong key)
{
  if (pMap == NULL)
  { 
    return (NULL_POINTER_ERROR);
  }

  ohmap* pTemp = (ohmap*)pMap;

  ohmap::const_iterator it = pTemp->find(key);
  if (it != pTemp->end())
  {
    pTemp->erase(it);
  }
  return (0);
}

DECAF_errno_t OpaqueHashmap_getVal(OpaqueHashmap* pMap, target_ulong key, void** pVal)
{
  if ( (pMap == NULL) || (pVal == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  ohmap* pTemp = (ohmap*)pMap;

  ohmap::const_iterator it = pTemp->find(key);
  if (it == pTemp->end())
  {
    return (-1);
  }

  *pVal = it->second;
  return (0);
}

int OpaqueHashmap_exist(OpaqueHashmap* pMap, target_ulong key)
{
  void* pTemp;

  return (OpaqueHashmap_getVal(pMap, key, &pTemp) == 0);
}

void OpaqueHashmap_print(FILE* fp, OpaqueHashmap* pMap)
{
  ohmap* pTemp = (ohmap*)pMap;

  if (pTemp == NULL)
  {
    return;
  }

  for (ohmap::const_iterator it = pTemp->begin(); it != pTemp->end(); it++)
  {
    DECAF_fprintf(fp, "  %x -> %p \n", it->first, it->second);
  }
}

DECAF_errno_t OpaqueHashmap_getFront(OpaqueHashmap* pMap, target_ulong* pKey, void** pVal)
{
  if ( (pMap == NULL) || (pKey == NULL) || (pVal == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }
  
  ohmap* pTemp = (ohmap*)pMap;
 
  ohmap::iterator it = pTemp->begin();
  if (it == pTemp->end())
  {
    return (-1);
  }

  *pKey = it->first;
  *pVal = it->second;
  return (0);
}

int OpaqueHashmap_isEmpty(OpaqueHashmap* pMap)
{
  if (pMap == NULL)
  {
    return (1);
  }

  ohmap* pTemp = (ohmap*)pMap;
  
  return (pTemp->empty());
}

DECAF_errno_t OpaqueHashmap_removeFront(OpaqueHashmap* pMap)
{
  if (pMap == NULL)
  {
    return (NULL_POINTER_ERROR);
  }
  
  ohmap* pTemp = (ohmap*)pMap;
 
  ohmap::const_iterator it = pTemp->begin();
  if (it == pTemp->end())
  {
    return (-1);
  }

  pTemp->erase(it);
  return (0);
}
