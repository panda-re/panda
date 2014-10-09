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
 * Uint32StringMapWrapper.h
 *
 *  Created on: Jan 4, 2012
 *      Author: lok
 */

#ifndef TARGET_ULONG_STRING_MAP_WRAPPER_H_
#define TARGET_ULONG_STRING_MAP_WRAPPER_H_

#include "linux_vmi_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

  #include <stdio.h>

  typedef struct TULStrMap TULStrMap;

  TULStrMap* TULStrMap_new(void);
  void TULStrMap_free(TULStrMap* pMap);
  void TULStrMap_print(TULStrMap* pMap, FILE* fp);
  DECAF_errno_t TULStrMap_add(TULStrMap* pMap, uint32_t key, const char* val);
  DECAF_errno_t TULStrMap_getVal(TULStrMap* pMap, char* str, size_t len, uint32_t key);
  TULStrMap* TULStrMap_newFromFile(const char* filename);
  DECAF_errno_t TULStrMap_loadFromFile(TULStrMap* pMap, const char* filename);
  DECAF_errno_t TULStrMap_saveToFile(TULStrMap* pMap, const char* filename);

#ifdef __cplusplus
}

#include <tr1/unordered_map>
#include <string>
#include <fstream>


class TULStringMap
{
public:
  TULStringMap() {};
  void printMap(std::ostream& outs);
  void printMap(FILE* fp);
  DECAF_errno_t addSymbol(target_ulong address, const std::string& sym);
  DECAF_errno_t readSymbolsFromFile(const std::string& filename);
  DECAF_errno_t readSymbolsFromFile(const char* filename);
  DECAF_errno_t saveSymbolsToFile(const std::string& filename);
  DECAF_errno_t saveSymbolsToFile(const char* filename);
  bool symbolExists(target_ulong address);
  DECAF_errno_t getSymbol(std::string& str, target_ulong address);
  DECAF_errno_t getSymbol(char* str, size_t len, target_ulong address);

protected:
  /**
   * Maps offsets to strings.
   */
  typedef std::tr1::unordered_map<target_ulong, std::string> _map;

  _map symbols;
};
#endif //__cplusplus

#endif /* TARGET_ULONG_STRING_MAP_WRAPPER_H_ */
