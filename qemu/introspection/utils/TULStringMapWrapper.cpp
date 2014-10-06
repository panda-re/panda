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
 * TULStringMapWrapper.cpp
 *
 *  Created on: Jan 4, 2012
 *      Author: lok
 */

#include <iostream>
#include <iomanip>
#include "utils/TULStringMapWrapper.h"
#include "utils/HelperFunctions.h"
#include <cstring>

using namespace std;

int TULStringMap::addSymbol(target_ulong address, const std::string& sym)
{
  symbols[address] = sym;
  return (0);
}

int TULStringMap::getSymbol(std::string& str, target_ulong address)
{
  _map::const_iterator it;
  it = symbols.find(address);
  if (it == symbols.end())
  {
    return (ITEM_NOT_FOUND_ERROR);
  }
  str = it->second;
  return (0);
}

int TULStringMap::getSymbol(char* str, size_t len, target_ulong address)
{
  if ( str == NULL )
  {
    return (NULL_POINTER_ERROR);
  }

  _map::const_iterator it;
  it = symbols.find(address);
  if (it == symbols.end())
  {
    return (ITEM_NOT_FOUND_ERROR);
  }

  strncpy(str, (it->second).c_str(), len);
  return (0);
}

bool TULStringMap::symbolExists(target_ulong address)
{
  return (symbols.find(address) != symbols.end());
}

int TULStringMap::readSymbolsFromFile(const std::string& filename)
{
  if (filename.empty())
  {
    return (-1);
  }
  
  ifstream ifs(filename.c_str(), ifstream::in);
  string s;

  target_ulong addr;
  string sym;

  size_t t;
  int ret = 0;

  while (ifs.good())
  {
    getline(ifs, s);
    if (s.empty())
    {
      continue;
    }
    t = s.find_first_of(',');
    if (t == string::npos)
    {
      continue;
    }
    ret = myHexStrToul<target_ulong>(addr, s.substr(0,t));
    if (ret != 0)
    {
      cerr << "readTULStringMap: Error [" << ret << "] with the following line [" << s << "]" << endl;
      continue;
    }
    sym = s.substr(t+1);
    symbols[addr] = sym;
  }

  if (symbols.empty())
  {
    return (-1);
  }
  return (0);
}

int TULStringMap::readSymbolsFromFile(const char* filename)
{
  if (filename == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  string s(filename);

  //being lazy
  return (readSymbolsFromFile(s));
}

int TULStringMap::saveSymbolsToFile(const std::string& filename)
{
  if (filename.empty())
  {
    return (-1);
  }

  ofstream ofs(filename.c_str(), ofstream::out);
  if (!ofs.good())
  {
    return (-2);
  }

  printMap(ofs);
  return (0);
}

int TULStringMap::saveSymbolsToFile(const char* filename)
{
  if (filename == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  FILE* fp = fopen(filename, "w");
  if (fp == NULL)
  {
    return (FILE_OPEN_ERROR);
  }

  printMap(fp);

  fclose(fp);

  return (0);
}

void TULStringMap::printMap(ostream& outs)
{
  _map::const_iterator it;

  for (it = symbols.begin(); it != symbols.end(); it++)
  {
    outs << setw(8) << setfill('0') << hex << (*it).first << "," << (*it).second << endl;
  }
}

void TULStringMap::printMap(FILE* fp)
{
  if (fp == NULL)
  {
    return;
  }

  _map::const_iterator it;


  for (it = symbols.begin(); it != symbols.end(); it++)
  {
    fprintf(fp, "0x%08x, %s\n", (*it).first, ((*it).second).c_str());
  }
}

//C parts
TULStrMap* TULStrMap_new()
{
  return ((TULStrMap*) new (TULStringMap));
}

void TULStrMap_free(TULStrMap* pMap)
{
  if (pMap != NULL)
  {
    delete ( (TULStringMap*)pMap );
  }
}

void TULStrMap_print(TULStrMap* pMap, FILE* fp)
{
  if (pMap != NULL)
  {
    TULStringMap* pUMap = (TULStringMap*)pMap;
    pUMap->printMap(fp);
  }
}

int TULStrMap_add(TULStrMap* pMap, target_ulong key, const char* val)
{
  if (pMap == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  TULStringMap* pUMap = (TULStringMap*)pMap;
  return (pUMap->addSymbol(key, val));
}

int TULStrMap_getVal(TULStrMap* pMap, char* str, size_t len, target_ulong key)
{
  if ( (pMap == NULL) || (str == NULL) )
  {
   return (NULL_POINTER_ERROR);
  }

  TULStringMap* pUMap = (TULStringMap*)pMap;
  return (pUMap->getSymbol(str, len, key));
}

TULStrMap* TULStrMap_newFromFile(const char* filename)
{
  TULStringMap* pUMap = new TULStringMap;

  if (pUMap == NULL)
  {
    return (NULL);
  }

  if (pUMap->readSymbolsFromFile(filename) < 0)
  {
    delete pUMap;
    pUMap = NULL;
  }

  return ((TULStrMap*)pUMap);
}

int TULStrMap_loadFromFile(TULStrMap* pMap, const char* filename)
{
  if ( pMap == NULL )
  {
    return (NULL_POINTER_ERROR);
  }

  TULStringMap* pUMap = (TULStringMap*)pMap;

  return (pUMap->readSymbolsFromFile(filename));
}

int TULStrMap_saveToFile(TULStrMap* pMap, const char* filename)
{
  if ( pMap == NULL )
  {
  return (NULL_POINTER_ERROR);
  }

  TULStringMap* pUMap = (TULStringMap*)pMap;

  return (pUMap->saveSymbolsToFile(filename));
}
