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
 * ModuleInfo.h
 *
 *  Created on: Sep 14, 2011
 *      Author: lok
 */

#ifndef MODULEINFO_H_
#define MODULEINFO_H_

#include <string>
#include <inttypes.h>
#include "DroidScope/DS_utils/SymbolMap.h"

class ModuleInfo : public SymbolMap
{
public:
  ModuleInfo(const std::string& name) : SymbolMap() { moduleName = name; }
  const std::string& getName() { return moduleName; }
  int getSymbol(std::string& str, uint32_t address)
  {
    std::string s;
    int ret = SymbolMap::getSymbol(s, address);
    if (ret == 0)
    {
      str = moduleName;
      str.append(":");
      str.append(s);
    }
    return (ret);
  }

  int getNearestSymbol(std::string& str, uint32_t address)
  {
    std::string s;
    int ret = SymbolMap::getNearestSymbol(s, address);
    if (ret == 0)
    {
      str = moduleName;
      str.append(":");
      str.append(s);
    }
    return (ret);
  }
protected:
  std::string moduleName;
};

#endif /* MODULEINFO_H_ */
