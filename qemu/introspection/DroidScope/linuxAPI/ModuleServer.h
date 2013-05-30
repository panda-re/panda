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
 * ModuleServer.h
 *
 *  Created on: Sep 15, 2011
 *      Author: lok
 */

#ifndef MODULESERVER_H_
#define MODULESERVER_H_

#include <list>
#include "ModuleInfo.h"

/**
 * I decided to create a ModuleServer class so we can manage all of the different modules
 * I think there might be a time when we will need to delete modules (to free up memory) in the future
 * instead of just leaving all of the modules in memory as we are doing now.
 * In that case, we can implement functions that keeps track of the number of pointers
 * pointing to the modules and only when it is 0 do we delete the module object itself.
 * But that is not implemented now
 */
class ModuleServer
{
public:
  ModuleServer() {}
  ModuleInfo* getModulePointer(const std::string& name);
  ~ModuleServer();
protected:
  std::list<ModuleInfo*> modules;
};

#endif /* MODULESERVER_H_ */
