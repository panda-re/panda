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
 * LinuxAPI.h
 *
 *  Created on: Oct 7, 2011
 *      Author: lok
 */

#ifndef LINUXAPI_H_
#define LINUXAPI_H_

#include "DS_Common.h"

/******************************************************************************
 * TYPES
 *****************************************************************************/


/******************************************************************************
 * EVENTS API SECTION
 *****************************************************************************/



/******************************************************************************
 * CONTROL API SECTION
 *****************************************************************************/
#define UPDATE_PROCESSES (1 << 0)
#define UPDATE_THREADS (1 << 1)
#define UPDATE_MODULES (1 << 2)

/**
 * Updates a process's module list
 * @param pid The process's PID
 */
void updateProcessModuleList(CPUState* env, gpid_t pid);

/**
 * Updates a single process in the shadow process list
gva_t updateProcessListByTask(CPUState* env, gva_t task, int bNeedMark, int updateMask);
**/
gva_t updateProcessListByTask(CPUState* env, gva_t task, int updateMask, int bNeedMark);

/**
 * Updates the process list.
 * @param pgd - PGD is the current PGD, this is used for determining if the command name (which is in the userland) is available
 */
void updateProcessList(CPUState* env, gva_t pgd, int updateMask);

/**
 * Returns the PID of the currently executing task
 * @return PID of the currently executing task - according to the shadow list
 */
gpid_t getCurrentPID(void);

/**
 * Returns the PGD of the currently executing task - according to the shadow list
 * @return PGD
 */
gva_t getCurrentPGD(void);

/**
 * Returns the name - or actually a const pointer to the internal name of the currently executing process
 * @return Pointer to the name
 */
const char* getCurrentName(void);

/**
 * Update the contents of a process in the shadow process list. Only values
 *   that are different are updated.
 * @param pid
 * @param parentPid
 * @param tgid
 * @param glpid
 * @param uid
 * @param gid
 * @param euid
 * @param egid
 * @param pgd
 * @param strName
 * @param strComm
 * @return The number of values updated or negative values if error
 */
#define DS_PROC_TASK_MASK (1 << 0)
#define DS_PROC_PID_MASK (1 << 1)
#define DS_PROC_PPID_MASK (1 << 2)
#define DS_PROC_TGID_MASK (1 << 3)
#define DS_PROC_GLPID_MASK (1 << 4)
#define DS_PROC_UID_MASK (1 << 5)
#define DS_PROC_GID_MASK (1 << 6)
#define DS_PROC_EUID_MASK (1 << 7)
#define DS_PROC_EGID_MASK (1 << 8)
#define DS_PROC_PGD_MASK (1 << 9)
#define DS_PROC_ARGNAME_MASK (1 << 10)
#define DS_PROC_COMMNAME_MASK (1 << 11)
int updateProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, target_asid_t pgd, const char* strName, const char* strComm);

DECAF_errno_t updateProcessArgName(gpid_t pid, const char* argname);

/**
 * Removes a process from the list based on its PID. - This needs to include the TGID otherwise there might be a bug.
 * @param pid
 * @return
 */
int removeProcess(gpid_t pid);

/**
 * Adds a new process. If the process already exists in the list, then it will get overwritten.
 * @param pid
 * @param parentPid
 * @param tgid
 * @param glpid
 * @param uid
 * @param gid
 * @param euid
 * @param egid
 * @param pgd
 * @param strName
 * @param strComm
 * @return
 */
int addProcess(gva_t task, gpid_t pid, gpid_t parentPid, gpid_t tgid, gpid_t glpid, target_ulong uid, target_ulong gid, target_ulong euid, target_ulong egid, target_asid_t pgd, const char* strName, const char* strComm);

int addThread(gpid_t pid, gpid_t tid, gva_t threadInfo);

int removeThread(gpid_t pid, gpid_t tid);

int clearThreads(gpid_t pid);

/**
 * Print the process list into file pointed to by FP. Uses DECAF_fprintf.
 * @param fp
 * @return
 */
int printProcessList(FILE* fp);

int printThreadsList(FILE* fp);

/**
 * Destroy the process list.
 */
void destroyProcessList(void);

/**
 * Adds a new module to a process. Uses updateModule. TODO: Need to make sure that the pid and tgid are both used.
 * @param pid
 * @param startAddr
 * @param endAddr
 * @param flags
 * @param strName
 * @return
 */
int addModule(gpid_t pid, gva_t startAddr, gva_t endAddr, target_ulong flags, const char* strName);

/**
 * Updates (or adds) a new module to a process.
 * The parameters are the same as addModule.
 * @return negative value if error (-1 means error in the ranges and -2 should never be returned - i.e. error in the logic)
 * @return A mask of the items updated is returned with bit 0 begin startAddr, 1 begin endAddr, 2 flags and 3 the name. So 0xF means all items are updated - i.e. the entry is new.
**/
#define DS_MOD_STARTADDR_MASK (1 << 0)
#define DS_MOD_ENDADDR_MASK (1 << 1)
#define DS_MOD_FLAGS_MASK (1 << 2)
#define DS_MOD_NAME_MASK (1 << 3)
int updateModule(gpid_t pid, gva_t startAddr, gva_t endAddr, target_ulong flags, const char* strName);

/**
 * Remove a module by its name.
 * @param pid
 * @param strName
 * @return
 */
int removeModuleByName(gpid_t pid, const char* strName);

/**
 * Prints a process's module list to the screen.
 * @param fp
 * @param pid
 */
void printModuleList(FILE* fp, gpid_t pid);

/**
 * Request that the Shadow Task List be updated on the next context switch
 * @param env
 */
void requestProcessUpdate(void);

/******************************************************************************
 * ACCESS API SECTION
 *****************************************************************************/
/**
 * Determines whether a symbol is associated with address
 * @param pid
 * @param address
 * @return 1 If a symbol exists. 0 Otherwise
 */
int symbolExists(gpid_t pid, gva_t address);

/**
 * Retrieves the symbol at address address from the process with pid pid and copy it into symbol
 * with maximum length len.
 * @param symbol The buffer where the symbol should be copied to
 * @param len Maximum characters to copy
 * @param pid The process' PID
 * @param address The address
 * @return 0 If successful. Error codes otherwise.
 */
int getSymbol(char* symbol, size_t len, gpid_t pid, gva_t address);

/**
 * Given a symbol, retrieve the address of the symbol inside the module for process with pid pid
 * @param pid The process' PID
 * @param strModule The module name
 * @param strSymbol The symbol name
 * @return The address if its available or INV_ADDR if its not
 */
gva_t getSymbolAddress(gpid_t pid, const char* strModule, const char* strSymbol);

/**
 * Get the nearest symbol associated with address. The search returns the symbol who's address
 * is closest to <= address. The idea is that if functions are packed together, this function
 * will tell you what function (i.e. symbol) this instruction (e.g. address) belongs to
 * @param symbol The buffer where the symbol should be copied into
 * @param len Maximum number of characters to copy
 * @param pid The process' pID
 * @param address The address
 * @return 0 If successful, error codes otherwise.
 */
int getNearestSymbol(char* symbol, size_t len, gpid_t pid, gva_t address);

/**
 * Returns a pointer to the ProcessInfo structure with pid
 * @param pid The PID
 * @return Pointer, otherwise NULL if not found
 */
ProcessInfo* findProcessByPID(gpid_t pid);

/**
 * Returns a pointer to the ProcessInfo structure with pgd
 * @param pgd The PGD to look for
 * @return Pointer to the structure otherwise NULL if not found
 */
ProcessInfo* findProcessByPGD(target_asid_t pgd);

/**
 * Returns a pointer to the ProcessInfo structure with name
 * @param strName The name
 * @return Pointer to the structure otherwise NULL if not found
 */
ProcessInfo* findProcessByName(const char* strName);

/**
 * Tells if the process with pid exists in the shadow list
 * @param pid
 * @return
 */
int processExist(gpid_t pid);

/**
 * Tells if a process with pgd exists in the shadow list
 * @param pgd
 * @return
 */
int processExistByPGD(target_asid_t pgd);

/**
 * Tells if a process with the name strName exists. This function first
 * compares the name with the ARG name and then the command name.
 * @param strName
 * @return
 */
int processExistByName(const char* strName);

/**
 * Returns the module's name given an address. Similar to getSymbol.
 * @param pid The process's pid
 * @param str Where the name should go
 * @param len The maximum characters to copy
 * @param addr The address
 * @return 0 if successful. Error code if not.
 */
int getModuleName(gpid_t pid, char* str, size_t len, gva_t addr);

/**
 * Returns all of the module's information associated with the module at address addr
 * @param pid THe process' pid
 * @param str Where the name goes
 * @param len The maximum number of characters
 * @param pStartAddr Where the start address should go
 * @param pEndAddr Where the end address should go
 * @param addr The address
 * @return
 */
int getModuleInfo(gpid_t pid, char* str, size_t len, gva_t* pStartAddr, gva_t* pEndAddr, gva_t addr);

/**
 * Returns the module's information by first finding the module by its name
 * @param pid The process' pid
 * @param pStartAddr Where the start address should go
 * @param pEndAddr Where the end address should go
 * @param strName The module's name
 * @return
 */
int getModuleInfoByName(gpid_t pid, gva_t* pStartAddr, gva_t* pEndAddr, const char* strName);

//I just used the include here because there is a macro for static inline function definitions inside the h file.
// this is just a little cleaner that is all
#include "DECAF_linux_vmi.h"

#endif /* LINUXAPI_H_ */
