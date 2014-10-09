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
 * HashtableWrapper.h
 * A simple wrapper for the different kinds of hashtables that I have needed
 * to reference and use in the C side. Needs to be updated as new
 * requirements arise
 *
 *  Created on: Dec 21, 2011
 *      Author: lok
 */

#ifndef HASHTABLEWRAPPER_H_
#define HASHTABLEWRAPPER_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
  #include "cpu.h"

  //A regular unordered hashtable
  typedef struct Hashtable Hashtable;
  //A regular unordered hashmap
  typedef struct Hashmap Hashmap;
  //An unordered hashtable that also maintains a count
  // of the number of times a certain key has been added
  // and decremented when a key is removed
  typedef struct CountingHashtable CountingHashtable;
  //Similar to the counting hashtable
  typedef struct CountingHashmap CountingHashmap;

  typedef struct OpaqueHashmap OpaqueHashmap;

  Hashtable* Hashtable_new(void);
  void Hashtable_free(Hashtable* pTable);
  int Hashtable_add(Hashtable* pHash, target_ulong item);
  int Hashtable_remove(Hashtable* pHash, target_ulong item);
  int Hashtable_exist(Hashtable* pHash, target_ulong item);
  void Hashtable_print(FILE* fp, Hashtable* pHash);

  CountingHashtable* CountingHashtable_new(void);
  void CountingHashtable_free(CountingHashtable* pTable);
  /** Returns the count for the key **/
  size_t CountingHashtable_add(CountingHashtable* pHash, target_ulong item);
  /** Returns the count for the key **/
  size_t CountingHashtable_remove(CountingHashtable* pHash, target_ulong item);
  int CountingHashtable_exist(CountingHashtable* pHash, target_ulong item);
  size_t CountingHashtable_count(CountingHashtable* pTable, target_ulong key);
  void CountingHashtable_print(FILE* fp, CountingHashtable* pHash);

  Hashmap* Hashmap_new(void);
  void Hashmap_free(Hashmap* pMap);
  int Hashmap_add(Hashmap* pMap, target_ulong key, target_ulong val);
  int Hashmap_remove(Hashmap* pMap, target_ulong key, target_ulong val);
  Hashtable* Hashmap_getHashtable(Hashmap* pMap, target_ulong key);
  int Hashmap_exist(Hashmap* pMap, target_ulong from, target_ulong to);
  void Hashmap_print(FILE* fp, Hashmap* pMap);

  CountingHashmap* CountingHashmap_new(void);
  void CountingHashmap_free(CountingHashmap* pMap);
  size_t CountingHashmap_add(CountingHashmap* pMap, target_ulong key, target_ulong val);
  size_t CountingHashmap_remove(CountingHashmap* pMap, target_ulong key, target_ulong val);
  CountingHashtable* CountingHashmap_getCountingHashtable(CountingHashmap* pMap, target_ulong key);
  int CountingHashmap_exist(CountingHashmap* pMap, target_ulong from, target_ulong to);
  void CountingHashmap_print(FILE* fp, CountingHashmap* pMap);

  OpaqueHashmap* OpaqueHashmap_new(void);
  void OpaqueHashmap_free(OpaqueHashmap* pMap);
  DECAF_errno_t OpaqueHashmap_add(OpaqueHashmap* pMap, target_ulong key, void* val);
  DECAF_errno_t OpaqueHashmap_remove(OpaqueHashmap* pMap, target_ulong key);
  int OpaqueHashmap_exist(OpaqueHashmap* pMap, target_ulong key);
  DECAF_errno_t OpaqueHashmap_getVal(OpaqueHashmap* pMap, target_ulong key, void** pVal);
  void OpaqueHashmap_print(FILE* fp, OpaqueHashmap* pMap);

  /** Added so we can loop through the items to do any freeing
   * for the void*s
  **/

  /**
   * Returns the first element of the hashmap.
   * @return 0 If successful and the key and value into the locations pointed to by pKey and pVal
   * @return -1 If it is empty
   * @return Negative error codes
  **/
  DECAF_errno_t OpaqueHashmap_getFront(OpaqueHashmap* pMap, target_ulong* pKey, void** pVal);
  int OpaqueHashmap_removeFront(OpaqueHashmap* pMap);
  DECAF_errno_t OpaqueHashmap_isEmpty(OpaqueHashmap* pMap);

#ifdef __cplusplus
}
#endif
#endif /* HASHTABLEWRAPPER_H_ */
