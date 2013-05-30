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

/**
 * @author Lok Yan
 * @date 10/11/2011
 */

#ifndef DALVIK_API_H
#define DALVIK_API_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "introspection/DECAF_types.h"
#include "LinuxAPI.h"

/******************************************************************************
 * TYPES
 *****************************************************************************/

//include the AndroidHelperFunctions
#include "dalvik/vm/DvmDex.h"
#include "dalvik/libdex/DexProto.h"
#include "dalvik/vm/oo/Object.h"
#include "dalvik/vm/oo/Class.h"
#include "dalvik/vm/oo/Array.h"

#define DALVIK_INT 'I' //        width = 4;
#define DALVIK_CHAR 'C' //        width = 2;
#define DALVIK_BYTE 'B' //        width = 1;
#define DALVIK_BOOLEAN 'Z' //        width = 1;
#define DALVIK_FLOAT 'F' //        width = 4;
#define DALVIK_DOUBLE 'D' //        width = 8;
#define DALVIK_SHORT 'S' //        width = 2;
#define DALVIK_LONG 'J' //        width = 8;

/**
 * Index into StringObject.instanceData[x] to get the pointer to the Character Array
 */
# define STRING_INDEX_VALUE      0 //used to be 8
/**
 * Index into StringObject.instanceData[x] to get the 4-byte HASH value
 */
# define STRING_INDEX_HASHCODE   1 //12
/**
 * Index into StringObject.instanceData[x] to get the offset - ? Don't know what it is used for yet
 */
# define STRING_INDEX_OFFSET     2 //16
/**
 * Index into the StringObject.instanceData[x] to get the length of the string -
 * Not sure if the actual character array can be longer than this.
 */
# define STRING_INDEX_COUNT      3 //20

/**
 * The width of an Object Reference. This is used for arrays of objects.
 * Grabbed it from dalvik/vm/oo/Array.h
 */
#define REF_WIDTH    sizeof(Object*)


//forward declaration
struct TULStrMap;

/******************************************************************************
 * EVENTS API SECTION
 *****************************************************************************/
typedef enum {
  DS_DALVIK_INSN_BEGIN_CB = 0,
  DS_DALVIK_METHOD_BEGIN_CB,
  DS_DALVIK_LAST_CB,
} DS_Dalvik_callback_type_t;

typedef struct _DalvikInsnBegin_Params
{
  CPUState* env;
  gva_t dalvik_pc;
  uint32_t opcode; 
} DalvikInsnBegin_Params;

typedef struct _DalvikMethodBegin_Params
{
  CPUState* env;
  gva_t dalvik_pc;
} DalvikMethodBegin_Params;

typedef union _Dalvik_Callback_Params
{
  DalvikInsnBegin_Params ib;
  DalvikMethodBegin_Params mb;
} Dalvik_Callback_Params;

typedef void (*DS_Dalvik_callback_func_t) (Dalvik_Callback_Params* params);

DECAF_Handle DS_Dalvik_register_callback(
                DS_Dalvik_callback_type_t cb_type,
                DS_Dalvik_callback_func_t cb_func,
                int* cb_cond
                );

DECAF_errno_t DS_Dalvik_unregister_callback(DS_Dalvik_callback_type_t cb_type, DECAF_Handle handle);

/******************************************************************************
 * CONTROL API SECTION
 *****************************************************************************/

void DalvikDisableJit_init(gva_t getCodeAddr);
/**
 * Adds a new range to disable JIT for process with pid PID.
 * TODO: Support more pids than just 1.
 * @param pid The process's PID
 * @param startAddr The starting address of the range
 * @param endAddr The ending address - non inclusive
 * @return
 */
int addDisableJitRange(gpid_t pid, gva_t startAddr, gva_t endAddr);
int removeDisableJitRange(gpid_t pid, gva_t startAddr, gva_t endAddr);
DECAF_errno_t disableJitInitGetCodeAddr(gpid_t pid, gva_t getCodeAddr);
void DalvikDisableJit_close(void);

DECAF_errno_t mterp_initIBase(gpid_t pid, gva_t iBase);
DECAF_errno_t mterp_clear(gpid_t pid);
DECAF_errno_t addMterpOpcodesRange(gpid_t pid, gva_t startAddr, gva_t endAddr);
DECAF_errno_t removeMterpOpcodesRange(gpid_t pid, gva_t startAddr, gva_t endAddr);

void DalvikMterp_close(void);

/******************************************************************************
 * ACCESS API SECTION
 *****************************************************************************/

/**
 * These functions have target specific implementations
**/
target_ulong getDalvikPC(CPUState* env);
target_ulong getDalvikFP(CPUState* env);
target_ulong getDalvikGLUE(CPUState* env);
target_ulong getDalvikINST(CPUState* env);
target_ulong getDalvikIBASE(CPUState* env);

#define VREG_TO_GVA(_env, _vreg) ( getDalvikFP(_env) + ( (_vreg) * 4 ) )

/**
 * Gets the Dalvik Java Object at address addr from the memory contents of the MemoryBuilder.
 * @param addr The address of the Object, (Object *)
 * @param pObj Reference to an Object*. If successful, pObj will point to a NEW Object. NEEDS TO BE FREED!
 * @param pClazz Reference to a ClassObject*. If successful, pClazz will point to a new ClassObject that needs to be FREED.
 *   This is the contents of the ClassObject that the Object points to.
 * @returns 0 If successful
 */
int getObjectAt(CPUState* env, gva_t addr, Object** pObj, ClassObject** pClazz);

/**
 * Converts a Dalvik Java String into a String.
 * Dalvik Java Strings use UTF-16 encoding, so we need to change it back to a CString.
 * This function is based on the CString to UTF16 function in UtfString.c
 * And the dexGetUtf16FromUtf8 function in libdex/DexFile.h
 * @param pSO pointer to the StringObject to convert.
 * @param str Reference to a char* that will be malloced. NEEDS TO BE FREED!!!!
 * @return 0 If successful
 */
int convertJavaStringToString(CPUState* env, StringObject* pSO, char** str);

/**
 * A wrapper that uses both getObjectAt and convertJavaStringToString. Don't forget to delete the string after use.
 */
int getCStringFromJStringAt(CPUState* env, gva_t addr, char** str);

/**
 * Prints the java object's fields to the file pointed to by fp.
 * @param fp The output file
 * @param addr The address of the java object
 * @param pMap A pointer to the address-to-string map to use for getting object names and signatures.
 */
int printJavaObjectAt(FILE* fp, CPUState* env, gva_t addr, struct TULStrMap* pMap);

int printJavaStringAt(FILE* fp, CPUState* env, gva_t addr);

/**
 * Get the thread id given the address of the Glue structure
 */
uint32_t getDalvikThreadID(CPUState* env, int pid, gva_t pGlue);

int findProcessClassesDexFile(int pid, gva_t* pStart, gva_t* pEnd);

//Apparently this inlining doesn't work with gcc 4.6.1 in Oneiric so removing it
/**
 * returns the address of dvmASMInstructionStart, which is the instruction base
 * @param pid The process' pid - not used yet
 */
static inline gva_t getIBase(gpid_t pid)
{
  return(getSymbolAddress(pid, "/lib/libdvm.so", "dvmAsmInstructionStart"));
}

/**
 * returns the address of dvmJitGetCodeAddr
 */
static inline gva_t getGetCodeAddrAddress(gpid_t pid)
{
  return (getSymbolAddress(pid, "/lib/libdvm.so", "dvmJitGetCodeAddr"));
}

#ifdef __cplusplus
}
#endif

#endif//DALVIK_API_H
