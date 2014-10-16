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

/**
 * @author Lok Yan
**/

#include "DalvikAPI.h" //make sure we are implementing it correctly
#include "linuxAPI/ModuleInfo.h"
#include <string>

using namespace std;

int findProcessClassesDexFile(int pid, gva_t* pStart, gva_t* pEnd)
{
  if (pStart == NULL || pEnd == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  if (pInfo == NULL)
  {
    return (-1);
  }

  //since we have a process, we will go through the modules
  ModuleInfo* pModInfo = NULL;
  ModuleNode* i = pInfo->modules;
  for ( ; i != NULL; i = i->next)
  {
    pModInfo = (ModuleInfo*)(i->moduleInfo);
    if (pModInfo == NULL)
    {
      continue;
    }

    const string& strName = pModInfo->getName();

    //now that we have the name, lets see if its a dexfile or a native library

    if ( (strName.size() > 5) //.odex = 5 characters
         && (strName.compare(strName.size() - 5, 5, ".odex") == 0)
//         && (strName.compare(strName.size() - 11, 11, "classes.dex") == 0) //this could throw an exception so we check the size first
         && (strName.find(pInfo->strName) != string::npos) //we only use the strName because the comm name isn't long enough so it would be a waste
       )
    {
      *pStart = i->startAddr;
      *pEnd = i->endAddr;
      return (0);
    }
  }
  return (-1);
}

/*
static int parseDalvikMethodSymbol(char* sym, string& params, uint32_t& regs, uint32_t& ins)
{
  if (sym == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  size_t paramStart = 0;
  size_t insStart = 0;
  size_t regsStart = 0;

  string sTemp;
  size_t i = 0;
  for (i = 0; sym[i] != '\0'; i++) //first run through, just find the locations
  {
    if (sym[i] == '(')
    {
      paramStart = i; //this should always give us the LAST one;
    }
    if (sym[i] == ':')
    {
      regsStart = insStart;
      insStart = i;
    }
  }

  //lets first process the regs and ins
  if (regsStart == 0 || insStart == 0 || paramStart == 0)
  {
    return (-1);
  }

  //lets get regs first
  //to do this, we just set insStart to NULL
 *(sym + insStart) = '\0';

  regs = strtoul(sym + regsStart + 1, NULL, 10);
  *(sym + insStart) = ':';

  ins = strtoul(sym + insStart + 1, NULL, 10);

  params.clear(); // clear the params, if I have already been processing it

  for (i = paramStart + 1; (sym[i] != ')') && (i < regsStart); i++)
  {
    switch (sym[i])
    {
      case 'L': //this is an object so read ahead until we get to the ';'
      {
        //here we need to see if its java.lang.String, and if it is then change it to S
        // if not then just use an O
        //first increment i
        i++;
        static char javaLangString[] = "java/lang/String";
        bool bIsString = (sym[i] == 'j');
        for (int j = 0; (j < sizeof(javaLangString)) && (sym[i] != ';') && (i < regsStart); j++)
        {
          if (javaLangString[j] != sym[i])
          {
            bIsString = false;
          }
          i++;
        }

        //update i to make sure it is pointing to the end of the current parameter
        while (sym[i] != ';')
        {
          i++;
        }

        if (bIsString)
        {
          params.push_back('S');
        }
        else
        {
          params.push_back('_');
        }
        break; //for switch-case
      }
      case '[': //TODO: support arrays
      {
        break; //do nothing if its an array
      }
      default:
      {
        params.push_back(sym[i]);
      }
    }
  }

  return (0);
}


int printDalvikMethodPrototypeAtBeginning(FILE* fp, CPUState* env, int pid, gva_t addr, gva_t callerRPC, U32StrMap* classStrings)
{
  if (env == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  char sym[256];
  sym[0] = '\0';
  if (getSymbol(sym, 256, pid, addr) == 0)
  {
    DECAF_fprintf(fp, "[%x] [tid = %u] %s", callerRPC, getDalvikThreadID(pid, env->regs[rGLUE]), sym);
    string s;
    uint32_t regs = 0;
    uint32_t ins = 0;
    parseDalvikMethodSymbol(sym, s, regs, ins);
    //printf("sym = %s \n params = %s, regs = %u, ins = %u\n", sym, s.c_str(), regs, ins);
    //fflush(stdout);
    DECAF_fprintf(fp, ":%s", s.c_str());

    for (size_t i = 0; i < s.size(); i++)
    {
      uint32_t v5;
      DECAF_read_mem(env->regs[rFP] + ((regs - ins + i + (ins - s.size())) * 4), &v5, 4);

      if ( (s[i] == 'S') || (s[i] == '_') )
      {
        printJavaObjectAt(fp, v5, classStrings);
      }
      else
      {
        DECAF_fprintf(fp, ":[%08x]", v5);
      }
    }
    DECAF_fprintf(fp, "\n");
  }
}
*/
