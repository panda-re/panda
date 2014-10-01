/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
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
 * SymbolMap.cpp
 *
 *  Created on: Sep 14, 2011
 *      Author: lok
 */

#include <iostream>
#include <iomanip>
#include "DroidScope/DS_Common.h"
#include "DroidScope/DS_utils/SymbolMap.h"
#include "utils/HelperFunctions.h"
#include "utils/PreallocatedHistory.h"

using namespace std;

bool SymbolMap::isObjdumpTextLine(const string& str)
{
  //return (str.find(".text") != string::npos);
  //return (str.rfind(">:") != string::npos); //this should be the end I guess
  return (true);
}

int SymbolMap::getInfoFromObjdumpLine(const string& str, gva_t& add, string& sym)
{
  if (!isObjdumpTextLine(str))
  {
    return (-1);
  }

  size_t t1 = str.find_first_of(' ');
  if (t1 == string::npos)
  {
    return (-1);
  }

  size_t t2 = str.rfind(">:");
  if (t2 == string::npos)
  {
    return (-1);
  }

  size_t t3 = str.find_first_of('<');
  if ( (t3 == string::npos) || (t3 > t2) )
  {
    return (-1);
  }

  if (myHexStrToul<gva_t>(add, str.substr(0, t1)) < 0)
  {
    return (-1);
  }

  sym = str.substr(t3, t2+1);
  if (sym.empty())
  {
    return (-1);
  }

  return (0);

  /* This is objdump -t works, but it might not
  size_t t1 = str.find_first_of(' ');
  size_t t2 = str.find_last_of(' ');

  if (t1 == string::npos)
  {
    t1 = str.find_first_of('\t');
  }
  if (t2 == string::npos)
  {
    t2 = str.find_last_of('\t');
  }

  if ( (t1 == string::npos) || (t2 == string::npos) )
  {
    return (-1);
  }

  if (myHexStrToul(add, str.substr(0, t1)) < 0)
  {
    return (-1);
  }

  //we should have address here so lets get the symbol
  sym = str.substr(t2+1);

  if (sym.empty())
  {
    return (-1);
  }

  //we are done
  return (0);
  */
}

int SymbolMap::processObjdumpFile(const std::string& filename)
{
  ifstream tempFile(filename.c_str(), ifstream::in);
  if (!tempFile.good())
  {
    tempFile.close();
    return (-1);
  }

  string s;
  //now that we have the file open, we can process the symbols
  gva_t add = 0;
  string sym;

  while (tempFile.good())
  {
    getline(tempFile, s);
    if (s.empty())
    {
      continue;
    }
    if (getInfoFromObjdumpLine(s, add, sym) != 0)
    {
      continue;
    }
    symbols[add] = sym;
  }

  tempFile.close();
  return (0);
}

bool SymbolMap::isDexdumpMethodLine(const string& s)
{
  return (s.find("|[") != string::npos);
}


int SymbolMap::getInfoFromDexdumpLine(const string& str, gva_t& address, string& sym)
{
  if (!isDexdumpMethodLine(str))
  {
    return (-1);
  }

  size_t t1 = str.find_first_of("|[");
  size_t t2 = str.find(']', t1);

  if ( (t1 == string::npos) || (t2 == string::npos) )
  {
    return (-1);
  }

  if (myHexStrToul<gva_t>(address, str.substr(t1 + 2, t2 - t1 - 2)) != 0)
  {
    return (-1);
  }

  //we should have address here so lets get the symbol
  for (t2++ ; (t2 < str.size()) && ((str[t2] == ' ') || (str[t2] == '\t')); t2++);

  sym = str.substr(t2);

  if (sym.empty())
  {
    return (-1);
  }

  //ADD 0x28 to the address which is our offset from .sym to .dex
  //I figured this out when I compared the method output with the instructions
  // for example without this offset we get
  //[41694b20] system@framework@core.jar@classes.dex:java.util.AbstractMap.clone:()Ljava/lang/Object; - +invoke-direct-empty
  //if you look at the dump you will see
  //0d5b20:                                        |[0d5b20] java.util.AbstractMap.clone:()Ljava/lang/Object;
  //0d5b30: 1201                                   |0000: const/4 v1, #int 0 // #0
  //Obviously the instruction is not right
  //but if you go back 28 in the file you get
  //0d5af8: f010 0e0a 0000                         |0000: +invoke-direct-empty {v0}, Ljava/lang/Object;.<init>:()V // method@0a0e
  //which is the correct address
  //This is due to the ODEX header
  address += 0x28;

  //now we also add in the default 0x10 offset as well to make things perfect for the symbols due to the 0x10 offset for all methods
  address += 0x10;

  //we are done
  return (0);
}

/** The code is exactly the same as processObjdumpFile
 *
 * @param filename
 * @return
 */
int SymbolMap::processDexdumpFile(const std::string& filename)
{
  PreallocatedHistory<string> phis;

  ifstream tempFile(filename.c_str(), ifstream::in);
  if (!tempFile.good())
  {
    tempFile.close();
    return (-1);
  }

  //now that we have the file open, we can process the symbols
  gva_t add = 0;
  string sym;

  while (tempFile.good())
  {
    string& s = phis.getRefAndPush();
    getline(tempFile, s);
    if (s.empty())
    {
      continue;
    }
    if (getInfoFromDexdumpLine(s, add, sym) != 0)
    {
      continue;
    }
    //cout << "Adding symbol " << sym << endl;
    //now parse out the number of registers and their types
    //but for now let sjust print them out
    //cout << phis.at(6) << " == " << phis.at(7) << endl;
    //total virtual registers is at 6
    //total input registers is at 7
    size_t loc = phis.at(6).find_last_of(':');
    if ((loc != string::npos) && (phis.at(6).size() > loc+2))
    {
      sym += ':';
      sym += phis.at(6).substr(loc + 2);
    }

    loc = phis.at(7).find_last_of(':');
    if ((loc != string::npos) && (phis.at(7).size() > loc+2))
    {
      sym += ':';
      sym += phis.at(7).substr(loc + 2);
    }
    //cout << phis.at(6) << " == " << phis.at(7) << " == " << sym << endl;
    symbols[add] = sym;
  }

  tempFile.close();
  return (0);
}


gva_t SymbolMap::getSymbolAddress(const char* str)
{
  gva_t ret = INV_ADDR;
  if (str == NULL)
  {
    return (ret);
  }

  _map::const_iterator it;

  for (it = symbols.begin(); it != symbols.end(); it++)
  {
    if (it->second.compare(str) == 0)
    {
      ret = it->first;
      break;
    }
  }

  return (ret);
}

int SymbolMap::getNearestSymbol(std::string& str, gva_t address)
{
  _map::const_iterator it;
  _map::const_iterator it2 = symbols.end();
  gva_t curNearest = 0;

  for (it = symbols.begin(); it != symbols.end(); it++)
  {
    if ( (address >= it->first) && (it->first > curNearest) )
    {
      it2 = it;
      curNearest = it->first;
    }
  }

  if (it2 == symbols.end()) //this should never happen
  {
    return (-1);
  }

  str = it2->second;
  return (0);
}
