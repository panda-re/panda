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
 * ProcessInfo.cpp
 *
 *  Created on: Sep 6, 2011
 *      Author: lok
 */


#include <cstring>
#include <assert.h>
#include "DroidScope/DS_Common.h"
#include "DroidScope/linuxAPI/ProcessInfo.h"
#include "DroidScope/linuxAPI/ModuleInfo.h"
#include "utils/OutputWrapper.h"

//Implementation for the class
ProcessInfo* ProcessInfoMap::findProcessByPID(gpid_t pid)
{
  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);
  if (it == processInfoMap.end())
  {
    return (NULL);
  }
  return (it->second);
}

ProcessInfo* ProcessInfoMap::findProcessByPGD(gpa_t pgd)
{
  _ProcessInfoMap::iterator it;
  for (it = processInfoMap.begin(); it != processInfoMap.end(); it++)
  {
    ProcessInfo* pTemp = it->second;
    if (pTemp == NULL)
    {
      continue;
    }
    if (pTemp->pgd == pgd)
    {
      return (pTemp);
    }
  }
  return (NULL);
}

ProcessInfo* ProcessInfoMap::findProcessByName(const char* strName)
{
  if (strName == NULL)
  {
    return (NULL);
  }

  _ProcessInfoMap::iterator it;
  for (it = processInfoMap.begin(); it != processInfoMap.end(); it++)
  {
    ProcessInfo* pTemp = it->second;
    if (pTemp == NULL)
    {
      continue;
    }
    //check strName first
    if (strcmp(pTemp->strName, strName) == 0)
    {
      return (pTemp);
    }
    //now check strComm
    if (strcmp(pTemp->strComm, strName) == 0)
    {
      return (pTemp);
    }
  }
  return (NULL);
}

DECAF_errno_t ProcessInfoMap::addProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, gpa_t pgd, const char* strName, const char* strComm)
{
  if ( (strName == NULL) && (strComm == NULL) )
  {
    return (-1);
  }

  ProcessInfo* pInfo = NULL;
  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);


  if (it != processInfoMap.end())
  {
    //if it already exists, then free the pointer if it exists
    if (it->second != NULL)
    {
      delete(it->second);
      it->second = NULL;
    }
  }

  pInfo = new ProcessInfo;
  if (pInfo == NULL)
  {
    return (-1);
  }
  pInfo->task_struct = task;
  pInfo->pgd = pgd;
  pInfo->pid = pid;
  pInfo->tgid = tgid;
  pInfo->glpid = glpid;
  pInfo->uid = uid;
  pInfo->gid = gid;
  pInfo->euid = euid;
  pInfo->egid = egid;
  pInfo->parentPid = parentPid;
  pInfo->strName[0] = '\0';
  pInfo->strComm[0] = '\0';
  if (strName != NULL)
  {
    strncpy(pInfo->strName, strName, MAX_PROCESS_INFO_NAME_LEN);
  }
  if (strComm != NULL)
  {
    strncpy(pInfo->strComm, strComm, MAX_TASK_COMM_LEN);
  }
  pInfo->modules = NULL;
  pInfo->threads = NULL;

  processInfoMap[pid] = pInfo;

  return (0);
}

int ProcessInfoMap::updateProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, gpa_t pgd, const char* strName, const char* strComm)
{
  int ret = 0;

  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);
  if (it == processInfoMap.end())
  {
    return (-1);
  }
  ProcessInfo* pInfo = it->second;
  if (pInfo == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  assert(pInfo->pid == pid);

  if (task != pInfo->task_struct)
  {
    pInfo->task_struct = task;
    ret |= DS_PROC_TASK_MASK;
  }

  if (parentPid != pInfo->parentPid)
  {
    pInfo->parentPid = parentPid;
    ret |= DS_PROC_PPID_MASK;
  }

  if (tgid != pInfo->tgid)
  {
    pInfo->tgid = tgid;
    ret |= DS_PROC_TGID_MASK;
  }

  if (glpid != pInfo->glpid)
  {
    pInfo->glpid = glpid;
    ret |= DS_PROC_GLPID_MASK;
  }

  if (uid != pInfo->uid)
  {
    pInfo->uid = uid;
    ret |= DS_PROC_UID_MASK;
  }

  if (gid != pInfo->gid)
  {
    pInfo->gid = gid;
    ret |= DS_PROC_GID_MASK;
  }

  if (euid != pInfo->euid)
  {
    pInfo->euid = euid;
    ret |= DS_PROC_EUID_MASK;
  }

  if (egid != pInfo->egid)
  {
    pInfo->egid = egid;
    ret |= DS_PROC_EGID_MASK;
  }

  if (pgd != pInfo->pgd)
  {
    pInfo->pgd = pgd;
    ret |= DS_PROC_PGD_MASK;
  }

  if ((strName != NULL) && (strcmp(pInfo->strName, strName) != 0))
  {
    strncpy(pInfo->strName, strName, MAX_PROCESS_INFO_NAME_LEN);
    ret |= DS_PROC_ARGNAME_MASK;
  }

  if ((strComm != NULL) && (strcmp(pInfo->strComm, strComm) != 0))
  {
    strncpy(pInfo->strComm, strComm, MAX_TASK_COMM_LEN);
    ret |= DS_PROC_COMMNAME_MASK;
  }

  //shouldn't I destroy the module list?

  return (ret);
}

DECAF_errno_t ProcessInfoMap::updateProcessArgName(gpid_t pid, const char* strName)
{
  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);
  if (it == processInfoMap.end())
  {
    return (-1);
  }
  ProcessInfo* pInfo = it->second;
  if (pInfo == NULL)
  {
    return (-1);
  }

  assert(pInfo->pid == pid);

  if (strName != NULL)
  {
    strncpy(pInfo->strName, strName, MAX_PROCESS_INFO_NAME_LEN);
  }

  return (0);
}

DECAF_errno_t ProcessInfoMap::removeProcess(gpid_t pid)
{
  ModuleNode* pNode = NULL;
  ModuleNode* pNext = NULL;
  ThreadNode* pNodeT = NULL;
  ThreadNode* pNextT = NULL;
  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);
  if (it == processInfoMap.end())
  {
    return (0);
  }
  ProcessInfo* pInfo = it->second;
  if (pInfo != NULL)
  {

    pNext = pInfo->modules;
    //set the NULL value now - so worst that can happen is wasted memory
    pInfo->modules = NULL;

    for (pNode = pNext; pNode != NULL; pNode = pNext)
    {
      pNext = pNode->next;
      delete(pNode);
    }


    pNextT = pInfo->threads;
    pInfo->threads = NULL;

    for (pNodeT = pNextT; pNodeT != NULL; pNodeT = pNextT)
    {
      pNextT = pNodeT->next;
      delete(pNodeT);
    }


    delete (pInfo);

    pInfo = NULL;
  }
  processInfoMap.erase(it);
  return (0);
}

int ProcessInfoMap::addThread(gpid_t pid, gpid_t tid, gva_t threadInfoAddr)
{
  ThreadNode* pPrev = NULL;
  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);
  if (it == processInfoMap.end())
  {
    return (0);
  }
  ProcessInfo* pInfo = it->second;
  if (pInfo != NULL)
  {
    pPrev = pInfo->threads;
    if (pPrev == NULL)
    {
      pPrev = new ThreadNode;
      if (pPrev == NULL)
      {
        return (OOM_ERROR);
      }

      pPrev->tid = tid;
      pPrev->threadInfo = threadInfoAddr;
      pPrev->next = NULL;
      pInfo->threads = pPrev;
      return (0);
    }

    while (pPrev->next != NULL)
    {
      if (pPrev->tid == tid)
      {
        pPrev->threadInfo = threadInfoAddr;
        return (0);
      }
      pPrev = pPrev->next;
    }

    //pPrev->next == NULL
    if (pPrev->tid == tid)
    {
      pPrev->threadInfo = threadInfoAddr;
      return (0);
    }

    pPrev->next = new ThreadNode;
    if (pPrev->next == NULL)
    {
      return (OOM_ERROR);
    }
    pPrev->next->tid = tid;
    pPrev->next->threadInfo = threadInfoAddr;
    pPrev->next->next = NULL;

    return (0);
  }

  return (-1);
}

int ProcessInfoMap::removeThread(gpid_t pid, gpid_t tid)
{
  ThreadNode* pPrev = NULL;
  ThreadNode* pNext = NULL;
  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);
  if (it == processInfoMap.end())
  {
    return (0);
  }
  ProcessInfo* pInfo = it->second;
  if (pInfo != NULL)
  {
    pPrev = pInfo->threads;
    if (pPrev == NULL)
    {
      return (0);
    }
    if (pPrev->tid == tid)
    {
      pInfo->threads = pPrev->next;
      delete(pPrev);
      return (0);
    }

    //wasn't the first item in the list
    pNext = pPrev->next;
    while (pNext != NULL)
    {
      if (pNext->tid == tid)
      {
        pPrev->next = pNext->next;
        delete(pNext);
        return (0);
      }
      pPrev = pNext;
      pNext = pNext->next;
    }
  }

  return (-1);
}

int ProcessInfoMap::clearThreads(gpid_t pid)
{
  ThreadNode* pNode = NULL;
  ThreadNode* pNext = NULL;
  _ProcessInfoMap::iterator it;
  it = processInfoMap.find(pid);
  if (it == processInfoMap.end())
  {
    return (0);
  }
  ProcessInfo* pInfo = it->second;
  if (pInfo != NULL)
  {
    pNext = pInfo->threads;
    for (pNode = pNext; pNode != NULL; pNode = pNext)
    {
      pNext = pNode->next;
      delete(pNode);
    }

    pInfo->threads = NULL;
  }

  return (0);
}

int ProcessInfoMap::getPIDArray(gpid_t*& aPIDs, size_t& len)
{
  gpid_t* temp = NULL;
  if (aPIDs != NULL)
  {
    return (NON_NULL_POINTER_ERROR);
  }

  len = processInfoMap.size();
  if (len == 0)
  {
    return (0);
  }

  temp = (gpid_t*)malloc(sizeof(gpid_t) * len);
  if (temp == NULL)
  {
    len = 0;
    return (OOM_ERROR);
  }

  //now that we have the array, lets populate it
  _ProcessInfoMap::const_iterator it;
  size_t i = 0;
  for (it = processInfoMap.begin(); it != processInfoMap.end(); it++)
  {
    temp[i] = it->first;
    i++;
  }
  aPIDs = temp;
  return (0);
}

int ProcessInfoMap::printProcessList(FILE* fp)
{
  const char* strName = NULL;

  //We don't have to check fp == NULL since DECAF_fprintf handles it
  DECAF_fprintf(fp, "%5s %5s %6s %5s %5s %32s  %10s\n", "PID", "TGID", "Parent", "UID", "GID", "COMM", "PGD");
  _ProcessInfoMap::const_iterator it;
  for (it = processInfoMap.begin(); it != processInfoMap.end(); it++)
  {
    ProcessInfo* pTemp = it->second;
    if (pTemp == NULL)
    {
      return (-2);
    }
    if (pTemp->strName[0] != '\0')
    {
      strName = pTemp->strName;
    }
    else
    {
      strName = pTemp->strComm;
    }

    DECAF_fprintf(fp, "%5d %5d %6d %5d %5d %-32s  0x%08x\n", pTemp->pid, pTemp->tgid, pTemp->parentPid, pTemp->uid, pTemp->gid, strName, pTemp->pgd);
  }
  return (0);
}

int ProcessInfoMap::printThreadsList(FILE* fp)
{
  const char* strName = NULL;
  //We don't have to check fp == NULL since DECAF_fprintf handles it
  //DECAF_fprintf(fp, "%5s %5s %6s %5s %5s %32s  %10s\n", "PID", "TGID", "Parent", "UID", "GID", "COMM", "PGD");
  _ProcessInfoMap::const_iterator it;
  for (it = processInfoMap.begin(); it != processInfoMap.end(); it++)
  {
    ProcessInfo* pTemp = it->second;
    if (pTemp == NULL)
    {
      return (-2);
    }
    if (pTemp->strName[0] != '\0')
    {
      strName = pTemp->strName;
    }
    else
    {
      strName = pTemp->strComm;
    }

    DECAF_fprintf(fp, "\n");
    DECAF_fprintf(fp, "%5s %5s %6s %5s %5s %32s  %10s\n", "PID", "TGID", "Parent", "UID", "GID", "COMM", "PGD");
    DECAF_fprintf(fp, "%5d %5d %6d %5d %5d %-32s  0x%08x\n", pTemp->pid, pTemp->tgid, pTemp->parentPid, pTemp->uid, pTemp->gid, strName, pTemp->pgd);

    DECAF_fprintf(fp, "\t%5s, %8s\n", "TID", "&ThreadInfo");
    ThreadNode* pt = NULL;
    for (pt = pTemp->threads; pt != NULL; pt = pt->next)
    {
      DECAF_fprintf(fp, "\t%5d, 0x%08x\n", pt->tid, pt->threadInfo);
    }
  }
  return (0);
}

void ProcessInfoMap::printModuleList(FILE* fp, gpid_t pid)
{
  //We don't have to check fp == NULL since DECAF_fprintf handles it
  ProcessInfo* pInfo = findProcessByPID(pid);
  if (pInfo == NULL)
  {
    DECAF_fprintf(fp, "PROCESS [%d] does not exist\n", pid);
    return;
  }

  for (ModuleNode* pNode = pInfo->modules; pNode != NULL; pNode = pNode->next)
  {
    DECAF_fprintf(fp,"%08x-%08x %c%c%c%c\t", pNode->startAddr, pNode->endAddr,
          pNode->flags & 0x1 ? 'r' : '-', // VM_READ ? 'r' : '-',
          pNode->flags & 0x2 ? 'w' : '-', //VM_WRITE ? 'w' : '-',
          pNode->flags & 0x4 ? 'x' : '-', //VM_EXEC ? 'x' : '-',
          pNode->flags & 0x8 ? 's' : 'p'); //VM_MAYSHARE ? 's' : 'p');

    ModuleInfo* pModInfo = (ModuleInfo*)pNode->moduleInfo;
    if (pModInfo != NULL)
    {
      DECAF_fprintf(fp,"%s", pModInfo->getName().c_str());
    }
    DECAF_fprintf(fp, "\n");
  }
}

void ProcessInfoMap::destroy()
{
  _ProcessInfoMap::iterator it;
  ModuleNode* pNode = NULL;
  ModuleNode* pNext = NULL;
  while (!processInfoMap.empty())
  {
    it = processInfoMap.begin();
    ProcessInfo* pTemp = it->second;
    if (pTemp != NULL)
    {
      pNext = pTemp->modules;
      for (pNode = pNext; pNode != NULL; pNode = pNext)
      {
        pNext = pNode->next;
        delete(pNode);
      }
      delete(pTemp);
      pTemp = NULL;
    }
    processInfoMap.erase(it);
  }
}

DECAF_errno_t ProcessInfoMap::addModule(gpid_t pid, gva_t  startAddr, gva_t  endAddr, target_ulong flags, const char* strName)
{
  if (addModule(pid, startAddr, endAddr, flags, strName) > 0)
  {
    return (0);
  }
  return (-1);
}

int ProcessInfoMap::updateModule(gpid_t pid, gva_t  startAddr, gva_t  endAddr, target_ulong flags, const char* strName)
{
  int ret = 0;

  ProcessInfo* pInfo = findProcessByPID(pid);
  if (pInfo == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  ModuleNode* pNode = NULL;

  //remember that we are doing an ordered list
  //easiest is to first see if we need to insert into the front
  if ( (pInfo->modules == NULL) || (startAddr < pInfo->modules->startAddr) )
  {
    //module ranges should be mutually exclusive!!
    //TODO: Properly handle the case where a module was REBASED
    if ( (pInfo->modules != NULL) && (endAddr > pInfo->modules->startAddr) )
    {
      return (-1);
    }

    pNode = new ModuleNode;
    if (pNode == NULL)
    {
      return (OOM_ERROR);
    }
    pNode->startAddr = startAddr;
    pNode->endAddr = endAddr;
    pNode->flags = flags;
    pNode->next = pInfo->modules;
    pNode->moduleInfo = modServer.getModulePointer(strName);
    pInfo->modules = pNode;
    //we are done return 4 1's - the number of fields changed
    return (0xF);
  }

  ModuleNode* pi = NULL;
  //now lets run through the list to find the right place to put it
  for (pi = pInfo->modules ; pi != NULL; pi = pi->next)
  {
    //there are three terminating conditions
    // the first is the address already exists
    if (startAddr == pi->startAddr)
    {
      //In this case we need to see if there are any updates to the information
      if (endAddr != pi->endAddr)
      {
        //if they are different then we need to make sure that
        // the new address does not interfere with the next one
        if ( (pi->next != NULL) && (endAddr > pi->next->startAddr) )
        {
          return (-1);
        }
        //the new endAddr is valid so we update it
        pi->endAddr = endAddr;
        ret |= 0x2;
      }
      if (flags != pi->flags)
      {
        pi->flags = flags;
        ret |= 0x4;
      }
      
      void* moduleInfo = modServer.getModulePointer(strName);
      if (moduleInfo != pi->moduleInfo)
      {
        pi->moduleInfo = moduleInfo;
        ret |= 0x8;
      }
      return (ret);
    }
    //the second is if the next pointer is NULL
    //And the third is if the next pointer is not null but the address is
    // greater than the current, in which case we just insert it following the current
    //This is pretty much the same as the check we did before coming in here
    //remember that we are doing an ordered list

    if ( (pi->next == NULL) || (startAddr < pi->next->startAddr) )
    {
      //TODO: Properly handle the case where a module was REBASED
      if ( (pi->next != NULL) && (endAddr > pi->next->startAddr) )
      {
        return (-1);
      }

      pNode = new ModuleNode;
      if (pNode == NULL)
      {
        return (OOM_ERROR);
      }
      pNode->startAddr = startAddr;
      pNode->endAddr = endAddr;
      pNode->flags = flags;
      pNode->next = pi->next;
      pNode->moduleInfo = modServer.getModulePointer(strName);
      pi->next = pNode;
      //we are done
      return (0xF);
    }
  }

  return (-2); // we should never be here
}

int ProcessInfoMap::removeModuleByName(gpid_t pid, const char* strName)
{
  if (strName == NULL)
  {
      return (-1);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  if (pInfo == NULL)
  {
    return (-2);
  }

  ModuleNode* pNode = pInfo->modules;
  ModuleInfo* pModInfo = NULL;

  if (pNode == NULL)
  {
    return (0);
  }

  //if there is a module list lets check the head for a match
  pModInfo = (ModuleInfo*)pNode->moduleInfo;
  if (pModInfo != NULL)
  {
    if (pModInfo->getName().compare(strName) == 0)
    {
      pInfo->modules = pNode->next;
      delete(pNode);
      return (0);
    }
  }

  for ( ; pNode->next != NULL; pNode = pNode->next)
  {
    pModInfo = (ModuleInfo*)pNode->next->moduleInfo;
    if (pModInfo != NULL)
    {
      if (pModInfo->getName().compare(strName) == 0)
      {
        pNode->next = pNode->next->next;
        delete(pNode);
        return (0);
      }
    }
  }

  return (0);
}

int ProcessInfoMap::getModuleName(ProcessInfo* pInfo, char* str, size_t len, gva_t  addr)
{
  gva_t  startAddr;
  gva_t  endAddr;
  return (ProcessInfoMap::getModuleInfo(pInfo, str, len, &startAddr, &endAddr, addr));
}

int ProcessInfoMap::getModuleInfo(ProcessInfo* pInfo, char* str, size_t len, gva_t * pStartAddr, gva_t * pEndAddr, gva_t  addr)
{
  if ( (pInfo == NULL) || (str == NULL) || (pStartAddr == NULL) || (pEndAddr == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  //since we have a process, we need to find the right module
  ModuleInfo* pModInfo = NULL;
  ModuleNode* i = pInfo->modules;
  for ( ; i != NULL; i = i->next)
  {
    if ( (addr >= i->startAddr) && (addr <= i->endAddr) )
    {
      pModInfo = (ModuleInfo*)(i->moduleInfo);
      break;
    }
  }

  if (pModInfo == NULL)
  {
    return (ITEM_NOT_FOUND_ERROR);
  }

  strncpy(str, pModInfo->getName().c_str(),len);
  *pStartAddr = i->startAddr;
  *pEndAddr = i->endAddr;

  //if we are here then we found the right mod info, so lets just get the symbol and be done with it
  return (0);
}


int ProcessInfoMap::getModuleName(gpid_t pid, char* str, size_t len, gva_t  addr)
{
  if (str == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  return (ProcessInfoMap::getModuleName(pInfo, str, len, addr));
}

int ProcessInfoMap::getModuleInfo(gpid_t pid, char* str, size_t len, gva_t * pStartAddr, gva_t * pEndAddr, gva_t  addr)
{
  if ( (str == NULL) || (pStartAddr == NULL) || (pEndAddr == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  return (ProcessInfoMap::getModuleInfo(pInfo, str, len, pStartAddr, pEndAddr, addr));
}

int ProcessInfoMap::getModuleInfoByName(gpid_t pid, gva_t * pStartAddr, gva_t * pEndAddr, const char* strName)
{
  if ( (strName == NULL) || (pStartAddr == NULL) || (pEndAddr == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  return (ProcessInfoMap::getModuleInfoByName(pInfo, pStartAddr, pEndAddr, strName));
}

int ProcessInfoMap::symbolExists(ProcessInfo* pInfo, gva_t address)
{
  if (pInfo == NULL)
  {
    return (0);
  }

  //since we have a process, we need to find the right module
  ModuleInfo* pModInfo = NULL;
  ModuleNode* i = pInfo->modules;
  for ( ; i != NULL; i = i->next)
  {
    if ( (address >= i->startAddr) && (address <= i->endAddr) )
    {
      pModInfo = (ModuleInfo*)(i->moduleInfo);
      break;
    }
  }

  if (pModInfo == NULL)
  {
    return (0);
  }

  //if we are here then we found the right mod info, so lets just get the symbol and be done with it
  return (pModInfo->symbolExists(address - i->startAddr));
}

int ProcessInfoMap::symbolExists(gpid_t pid, gva_t address)
{
  ProcessInfo* pInfo = findProcessByPID(pid);
  return (ProcessInfoMap::symbolExists(pInfo, address));
}

int ProcessInfoMap::getSymbol(ProcessInfo* pInfo, char* symbol, size_t len, gva_t address)
{
  if (pInfo == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  //since we have a process, we need to find the right module
  ModuleInfo* pModInfo = NULL;
  ModuleNode* i = pInfo->modules;
  for ( ; i != NULL; i = i->next)
  {
    if ( (address >= i->startAddr) && (address <= i->endAddr) )
    {
      pModInfo = (ModuleInfo*)(i->moduleInfo);
      break;
    }
  }

  if (pModInfo == NULL)
  {
    return (-1);
  }

  //if we are here then we found the right mod info, so lets just get the symbol and be done with it
  std::string s;
  if (pModInfo->getSymbol(s, address - i->startAddr))
  {
    return (-1);
  }
  if (!s.empty())
  {
    strncpy(symbol, s.c_str(), len);
  }
  return (0);
}

int ProcessInfoMap::getModuleInfoByName(ProcessInfo* pInfo, gva_t * pStartAddr, gva_t * pEndAddr, const char* strName)
{
  if ( (pInfo == NULL) || (pStartAddr == NULL) || (pEndAddr == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  //since we have a process, we need to find the right module
  ModuleInfo* pModInfo = NULL;
  ModuleNode* i = pInfo->modules;
  for ( ; i != NULL; i = i->next)
  {
    pModInfo = (ModuleInfo*)(i->moduleInfo);
    if (pModInfo != NULL)
    {
      if (pModInfo->getName().compare(strName) == 0)
      {
        *pStartAddr = i->startAddr;
        *pEndAddr = i->endAddr;
        return (0);
      }
    }
  }

  return (-1);
}

int ProcessInfoMap::getSymbol(char* symbol, size_t len, gpid_t pid, gva_t address)
{
  if (symbol == NULL || len == 0)
  {
    return (-1);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  return (ProcessInfoMap::getSymbol(pInfo, symbol, len, address));
}

gva_t  ProcessInfoMap::getSymbolAddress(ProcessInfo* pInfo, const char* strModule, const char* strSymbol)
{
  if (pInfo == NULL)
  {
    return (INV_ADDR);
  }

  //since we have a process, we need to find the right module
  ModuleInfo* pModInfo = NULL;
  ModuleNode* i = pInfo->modules;
  gva_t  ret = INV_ADDR;
  for ( ; i != NULL; i = i->next)
  {
    pModInfo = (ModuleInfo*)(i->moduleInfo);
    if (pModInfo == NULL)
    {
      continue;
    }
    if (pModInfo->getName().compare(strModule) == 0) //if the modules match then find the address
    {
      ret = pModInfo->getSymbolAddress(strSymbol);
      if (ret != INV_ADDR)
      {
        ret += i->startAddr;
      }
      return (ret);
    }
  }

  return (ret);
}

gva_t  ProcessInfoMap::getSymbolAddress(gpid_t pid, const char* strModule, const char* strSymbol)
{
  if (strModule == NULL || strSymbol == NULL)
  {
    return (INV_ADDR);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  return (ProcessInfoMap::getSymbolAddress(pInfo, strModule, strSymbol));
}

int ProcessInfoMap::getNearestSymbol(ProcessInfo* pInfo, char* symbol, size_t len, gva_t address)
{

  if (pInfo == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  //since we have a process, we need to find the right module
  ModuleInfo* pModInfo = NULL;
  ModuleNode* i = pInfo->modules;
  for ( ; i != NULL; i = i->next)
  {
    if ( (address >= i->startAddr) && (address <= i->endAddr) )
    {
      pModInfo = (ModuleInfo*)(i->moduleInfo);
      break;
    }
  }

  if (pModInfo == NULL)
  {
    return (-1);
  }

  //if we are here then we found the right mod info, so lets just get the symbol and be done with it
  std::string s;
  if (pModInfo->getNearestSymbol(s, address - i->startAddr))
  {
    return (-1);
  }
  if (!s.empty())
  {
    strncpy(symbol, s.c_str(), len);
  }
  return (0);
}

//same as the previous function, except we call getNearestSymbol instead of getSymbol
int ProcessInfoMap::getNearestSymbol(char* symbol, size_t len, gpid_t pid, gva_t address)
{
  if (symbol == NULL || len == 0)
  {
    return (-1);
  }

  ProcessInfo* pInfo = findProcessByPID(pid);
  return (ProcessInfoMap::getNearestSymbol(pInfo, symbol, len, address));
}



/**
 * Beginning of the wrapper section
 */
//we need two of these guys to implement the removal of processes
ProcessInfoMap processInfoMap;
ProcessInfoMap processInfoMapTemp;
bool bInMarkMode = false;

int processMarkBegin()
{
  bInMarkMode = true;
  return (0);
}


int processMark(gpid_t pid)
{
  if (!bInMarkMode)
  {
    return (-1);
  }

  ProcessInfoMap::_ProcessInfoMap::iterator it;
  it = processInfoMap.processInfoMap.find(pid);
  if (it == processInfoMap.processInfoMap.end())
  {
    return (1);
  }

  processInfoMapTemp.processInfoMap[pid] = it->second;
  return (0);
}

//TODO: Like I mentioned before in Context.c this is NOT thread-safe
// it is possible to be upading the shadow list while someone else is using it
int processMarkEnd(gpid_t** aPIDs, size_t* len)
{
  int ret = 0;

  if (!bInMarkMode)
  {
    return (0);
  }

  ret = processInfoMap.size() - processInfoMapTemp.size();

  processInfoMap.processInfoMap.swap(processInfoMapTemp.processInfoMap);

  //THE MAP MUST BE ORDERED FOR THIS TO WORK
  if ( (aPIDs != NULL) && (len != NULL) && (ret > 0) )
  {
    //if the pointer is already pointing to something then just don't do anything
    if (*aPIDs != NULL)
    {
      ret = NON_NULL_POINTER_ERROR;
    }
    else
    {
      *len = ret;
      *aPIDs = (gpid_t*)malloc(sizeof(gpid_t) * ret);
      if (*aPIDs == NULL)
      {
        *len = 0;
        ret = OOM_ERROR;
      }
      else
      {
        //if we are here that means we are ready to find the entries that were removed
        size_t i = 0;
        ProcessInfoMap::_ProcessInfoMap::iterator it;
        ProcessInfoMap::_ProcessInfoMap::iterator it2;
        it = processInfoMap.processInfoMap.begin();
        it2 = processInfoMapTemp.processInfoMap.begin();
        //so how this works is to iterate through the bigger ordered list
        // e.g. ProcessInfoMapTemp and compare it with processInfoMap.
        // Then we keep copying values from Temp into the array until the two iterators
        // match again. This works because Map is a subset of Temp
        while (it2 != processInfoMapTemp.processInfoMap.end())
        {
          while ( (it2 != processInfoMapTemp.processInfoMap.end())
                  && ( (it == processInfoMap.processInfoMap.end())
                       || (it2->first != it->first)
                     )
                )
          {
            assert(i < *len);
            (*aPIDs)[i] = it2->first;
            i++;
            it2++;
          }
          if (it != processInfoMap.processInfoMap.end())
          {
            it++;
          }
          if (it2 != processInfoMapTemp.processInfoMap.end())
          {
            it2++;
          }
        }
        assert(i == (*len));
      }
    }
  }

  //now we can clear it
  processInfoMapTemp.clear();

  bInMarkMode = false;
  return (ret);
}

int removeProcess(gpid_t pid)
{
  return (processInfoMap.removeProcess(pid));
}

int updateProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, gpa_t pgd, const char* strName, const char* strComm)
{
  return (processInfoMap.updateProcess(task, pid, parentPid, tgid, glpid, uid, gid, euid, egid, pgd, strName, strComm));
}

DECAF_errno_t updateProcessArgName(gpid_t pid, const char* strName)
{
  return (processInfoMap.updateProcessArgName(pid, strName));
}

DECAF_errno_t addProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, gpa_t pgd, const char* strName, const char* strComm)
{
  return (processInfoMap.addProcess(task, pid, parentPid, tgid, glpid, uid, gid, euid, egid, pgd, strName, strComm));
}

int addThread(gpid_t pid, gpid_t tid, gva_t threadInfo)
{
  return (processInfoMap.addThread(pid, tid, threadInfo));
}

int removeThread(gpid_t pid, gpid_t tid)
{
  return (processInfoMap.removeThread(pid, tid));
}

int clearThreads(gpid_t pid)
{
  return (processInfoMap.clearThreads(pid));
}

void destroyProcessList()
{
  processInfoMap.clear();
}

int printProcessList(FILE* fp)
{
  return (processInfoMap.printProcessList(fp));
}

int printThreadsList(FILE* fp)
{
  return (processInfoMap.printThreadsList(fp));
}

ProcessInfo* findProcessByPID(gpid_t pid)
{
  return (processInfoMap.findProcessByPID(pid));
}

ProcessInfo* findProcessByPGD(gpa_t pgd)
{
  return (processInfoMap.findProcessByPGD(pgd));
}

ProcessInfo* findProcessByName(const char* strName)
{
  return (processInfoMap.findProcessByName(strName));
}

int processExist(gpid_t pid)
{
  return (findProcessByPID(pid) != NULL);
}

int processExistByPGD(gpa_t pgd)
{
  return (findProcessByPGD(pgd) != NULL);
}

int processExistByName(char* strName)
{
  return (findProcessByName(strName) != NULL);
}

int addModule(gpid_t pid, gva_t  startAddr, gva_t  endAddr, target_ulong flags, const char* strName)
{
  return (processInfoMap.addModule(pid, startAddr, endAddr, flags, strName));
}

int updateModule(gpid_t pid, gva_t  startAddr, gva_t  endAddr, target_ulong flags, const char* strName)
{
  return (processInfoMap.updateModule(pid, startAddr, endAddr, flags, strName));
}

int removeModuleByName(gpid_t pid, const char* strName)
{
  return (processInfoMap.removeModuleByName(pid, strName));
}

int getModuleName(gpid_t pid, char* str, size_t len, gva_t  addr)
{
  return (processInfoMap.getModuleName(pid, str, len, addr));
}

int getModuleInfo(gpid_t pid, char* str, size_t len, gva_t * pStartAddr, gva_t * pEndAddr, gva_t  addr)
{
  return (processInfoMap.getModuleInfo(pid, str, len, pStartAddr, pEndAddr, addr));
}

void printModuleList(FILE* fp, gpid_t pid)
{
  processInfoMap.printModuleList(fp, pid);
}

int symbolExists(gpid_t pid, gva_t address)
{
  return (processInfoMap.symbolExists(pid, address));
}

int getSymbol(char* symbol, size_t len, gpid_t pid, gva_t address)
{
  return (processInfoMap.getSymbol(symbol, len, pid, address));
}

gva_t  getSymbolAddress(gpid_t pid, const char* strModule, const char* strSymbol)
{
  return (processInfoMap.getSymbolAddress(pid, strModule, strSymbol));
}

int getNearestSymbol(char* symbol, size_t len, gpid_t pid, gva_t address)
{
  return (processInfoMap.getNearestSymbol(symbol, len, pid, address));
}

int getModuleInfoByName(gpid_t pid, gva_t * pStartAddr, gva_t * pEndAddr, const char* strName)
{
  return (processInfoMap.getModuleInfoByName(pid, pStartAddr, pEndAddr, strName));
}
