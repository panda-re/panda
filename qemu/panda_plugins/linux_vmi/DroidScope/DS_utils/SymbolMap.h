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
 * FunctionMap.h
 *
 *  Created on: Sep 14, 2011
 *      Author: lok
 */

#ifndef SYMBOLMAP_H_
#define SYMBOLMAP_H_

#include "utils/TULStringMapWrapper.h"

class SymbolMap : public TULStringMap
{
public:
  SymbolMap() {}
  bool isObjdumpTextLine(const std::string& str);
  int getInfoFromObjdumpLine(const std::string& str, gva_t& add, std::string& sym);
  int processObjdumpFile(const std::string& filename);
  bool isDexdumpMethodLine(const std::string& s);
  int getInfoFromDexdumpLine(const std::string& str, gva_t& add, std::string& sym);
  int processDexdumpFile(const std::string& filename);
  gva_t getSymbolAddress(const char* str);
  int getNearestSymbol(std::string& str, gva_t address);
};

#endif /* SYMBOLMAP_H_ */
