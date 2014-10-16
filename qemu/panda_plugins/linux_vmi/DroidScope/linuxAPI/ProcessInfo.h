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
 * ProcessInfo.h
 *
 *  Created on: Sep 6, 2011
 *      Author: lok
 */

#ifndef PROCESSINFO_H
#define PROCESSINFO_H

#ifdef __cplusplus

extern "C" {
#endif

//#include <inttypes.h>
//#include <stdio.h>
#include "DroidScope/LinuxAPI.h"

int processMarkBegin();
int processMark(gpid_t pid);
int processMarkEnd(gpid_t** aPIDs, size_t* len);

//here are some functions that can be used to cleanup the process list through removal
#ifdef __cplusplus
}

//The class
#include <map>
#include "ModuleServer.h"

class ProcessInfoMap
{
public:
  ProcessInfoMap(){} // nothing to do
  ProcessInfo* findProcessByPID(gpid_t pid);
  ProcessInfo* findProcessByPGD(gpa_t pgd);
  ProcessInfo* findProcessByName(const char* strName);
  ProcessInfo* findProcessByTaskStruct(gva_t task_struct_addr);

  int processExist(gpid_t pid) { return (findProcessByPID(pid) != NULL); }
  int processExistByPGD(gpa_t pgd) { return (findProcessByPGD(pgd) != NULL); }
  int processExistByName(const char* strName) { return (findProcessByName(strName) != NULL); }
  int updateProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, gpa_t pgd, const char* strName, const char* strComm);
  int updateProcessArgName(gpid_t pid, const char* argname);
  int addProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, gpa_t pgd, const char* strName, const char* strComm);
  int addThread(gpid_t pid, gpid_t tid, gva_t threadInfoAddr);
  int removeProcess(gpid_t pid);
  int removeThread(gpid_t pid, gpid_t tid);
  int clearThreads(gpid_t pid);
  int printProcessList(FILE* fp);
  int printThreadsList(FILE* fp);
  void printModuleList(FILE* fp, gpid_t pid);

  int size() {return (processInfoMap.size()); }

  void clear() { processInfoMap.clear(); }
  void destroy();

  friend int processMark(gpid_t pid);
  friend int processMarkEnd(gpid_t** aPIDs, size_t* len);


  int addModule(gpid_t pid, gva_t startAddr, gva_t endAddr, target_ulong flags, const char* strName);
  int updateModule(gpid_t pid, gva_t startAddr, gva_t endAddr, target_ulong flags, const char* strName);
  int removeModuleByName(gpid_t pid, const char* strName);
  int getModuleName(gpid_t pid, char* str, size_t len, gva_t addr);
  int getModuleInfo(gpid_t pid, char* str, size_t len, gva_t* pStartAddr, gva_t* pEndAddr, gva_t addr);
  int getModuleInfoByName(gpid_t pid, gva_t* pStartAddr, gva_t* pEndAddr, const char* strName);

  int symbolExists(gpid_t pid, gva_t address);
  int getSymbol(char* symbol, size_t len, gpid_t pid, gva_t address);
  gva_t getSymbolAddress(gpid_t pid, const char* strModule, const char* strSymbol);
  int getNearestSymbol(char* symbol, size_t len, gpid_t pid, gva_t address);
  int getPIDArray(gpid_t*& aPIDs, size_t& len);

  //static methods that gets the symbol information based on a ProcessInfo* -- THESE FUNCTIONS ARE DANGEROUS!!!
  // because the ProcessInfo itself could be destroyed
  static int symbolExists(ProcessInfo* pInfo, gva_t address);
  static int getModuleName(ProcessInfo* pInfo, char* str, size_t len, gva_t addr);
  static int getModuleInfo(ProcessInfo* pInfo, char* str, size_t len, gva_t* pStartAddr, gva_t* pEndAddr, gva_t addr);
  int getModuleInfoByName(ProcessInfo* pInfo, gva_t* pStartAddr, gva_t* pEndAddr, const char* strName);

  static int getSymbol(ProcessInfo* pInfo, char* symbol, size_t len, gva_t address);
  static gva_t getSymbolAddress(ProcessInfo* pInfo, const char* strModule, const char* strSymbol);
  static int getNearestSymbol(ProcessInfo* pInfo, char* symbol, size_t len, gva_t address);

  ~ProcessInfoMap() { destroy(); }

  typedef std::map<gpid_t, ProcessInfo*> _ProcessInfoMap;
private:
  _ProcessInfoMap processInfoMap;
  ModuleServer modServer;
};

#endif

#endif//PROCESSINFO_H
