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
 * ModuleServer.cpp
 *
 *  Created on: Sep 15, 2011
 *      Author: lok
 */

#include "ModuleServer.h"
//#include <iostream>
using namespace std;

ModuleInfo* ModuleServer::getModulePointer(const string& name)
{
  std::list<ModuleInfo*>::iterator it;

  //We would normally have to find the dump file and everything else
  // right now lets just assume that we have a "dumps" directory
  string dumpName = "dumps/out/";

  for (it = modules.begin(); it != modules.end(); it++)
  {
    //this is horrible should not happen
      //    DEFENSIVE_CHECK1( (*it == NULL), NULL );

    if (name.compare((*it)->getName()) == 0)
    {
      return (*it);
    }
  }

  //create the new module
  ModuleInfo* pInfo = new ModuleInfo(name);
  if (pInfo == NULL)
  {
    //OUT OF MEMORY
    return (NULL);
  }

  //TODO:right now we only support .so and .odex files so check for those
  size_t i = name.length();
  if (i < 5) //x.so is 4 characters - so that is the minimum length
  {
    goto push_and_end;
  }
 
  //first see if it is an so file
  switch(name[i-1])
  {
    case ('o'):
    {
      if ( (name[i-3] != '.') || (name[i-2] != 's') )
      {
        goto push_and_end;
      }
      break;
    }
    case ('x'):
    {
      if ( (i < 7) || (name[i-5] != '.') || (name[i-4] != 'o') || (name[i-3] != 'd') || (name[i-2] != 'e') )
      {
        goto push_and_end;
      }
      break;
    }
    default:
    {
      goto push_and_end;
    }
  }
   

  //now we need to see if its a dex file or a regular file, we can tell by the extension of the name
  dumpName.append(name);
  //now we will try to see if we can load the symbols first
  dumpName.append(".sym");
  pInfo->readSymbolsFromFile(dumpName);

push_and_end:
  modules.push_back(pInfo);
  return (pInfo);
}

ModuleServer::~ModuleServer()
{
  std::list<ModuleInfo*>::iterator it;

  for (it = modules.begin(); it != modules.end(); it++)
  {
    delete(*it);
    *it = NULL;
  }
  modules.clear();
}
