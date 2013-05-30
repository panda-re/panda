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
 *  @Author Lok Yan
 */

#include "introspection/DECAF_types.h"
#include "introspection/DECAF_config.h"
//#include "DECAF_shared/DECAF_main.h"
#include "introspection/utils/OutputWrapper.h"
#include "introspection/utils/TULStringMapWrapper.h"

#include "DalvikAPI.h"
#include "dalvikAPI/DalvikConstants.h"

int getObjectAt(CPUState* env, target_ulong addr, Object** pObj, ClassObject** pClazz)
{
  if ( (env == NULL) || (pObj == NULL) || (pClazz == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  if ( (*pObj != NULL) || (*pClazz != NULL) )
  {
    return (NON_NULL_POINTER_ERROR);
  }

  if (addr >= 0xC0000000)
  {
    return (MEM_READ_ERROR);
  }

  ArrayObject o;
  int ret = 0;

  //TODO: I am assuming that the minimum size of an object is always
  // greater than that of an ArrayObject!
  //Remember that pObj always comes first in the struct so this will work
  ret = DECAF_read_mem(env, addr, (void*)(&o), sizeof(ArrayObject));
  if (ret != 0)
  {
    return (ret);
  }

  //apparently need to do some sanity checking with all of these objects that we are reading out
  // so before DECAF_read_mem lets first make sure that the address is in userspace memory
  if (!IS_USERSPACE_ADDR((target_ulong)(o.obj.clazz)))
  {
    return (MEM_READ_ERROR);
  }

  //now that we have the class pointer, lets get the ClassObject itself
  *pClazz = (ClassObject*)(malloc(sizeof(ClassObject)));
  if (*pClazz == NULL)
  {
    return (OOM_ERROR);
  }

  ret = DECAF_read_mem(env, (target_ulong)o.obj.clazz, (void*)(*pClazz), sizeof(ClassObject));
  if (ret != 0)
  {
    free(*pClazz);
    *pClazz = NULL;
    return (ret);
  }

  //now that we have the ClassObject, we need to get the size

  //check to see if the size is 0 or not, if it is not then we are safe - this is just an object
  // if it is then its likely an array - it is possible that it is an interface or abstract class, but we have problems
  // if that is the case since those types of classes can't have objects!
  //TODO: Do we need to do some kind of sanity check for the object size as well?
  if ((*pClazz)->objectSize != 0)
  {
    *pObj = (Object*)(malloc((*pClazz)->objectSize));
    if (*pObj == NULL)
    {
      free(*pClazz);
      *pClazz = NULL;
      return (OOM_ERROR);
    }
    ret = DECAF_read_mem(env, addr, (*pObj), (*pClazz)->objectSize);
    if (ret != 0)
    {
      free(*pObj);
      *pObj = NULL;
      free(*pClazz);
      *pClazz = NULL;
      return (ret);
    }
    return (0);
  }

  //if we are here this should be an array - or it could be an interface or abstract class, but
  // that should not be possible!
  // keep in mind that an array of primitive types is different from an array of objects
  // including an array of arrays of something in which case, the "arrays of something" is itself an Object
  // this means that string[][] has an array of references to array of references to string
  // int[][] has an array of references to array of ints

  if ((*pClazz)->arrayDim < 1)
  {
    free(*pClazz);
    *pClazz = NULL;
    return (-1); //this is a problem if the arrayDimension is less than 1
  }

  if (!IS_USERSPACE_ADDR((target_ulong)((*pClazz)->descriptor)))
  {
    free(*pClazz);
    *pClazz = NULL;
    return (MEM_READ_ERROR);
  }

  //now check to see if this is an array of a primitive type
  // we do this by looking at the class descriptor - as mentioned in Object.h
  //
  char desc[5] = "";
  ret = DECAF_read_mem(env, (target_ulong)((*pClazz)->descriptor), desc, 5);
  if (ret != 0)
  {
    free(*pClazz);
    *pClazz = NULL;
    return (ret);
  }

  //now that we have the descriptor string, lets see what size we are looking for
  if ( (desc[0] == '\0') || (desc[1] == '\0') ) //if the len is less than 2
  {
    free(*pClazz);
    *pClazz = NULL;
    return (-15);
  }

  size_t width = 0;
  //grabbed it from dalvik/vm/oo/Array.c
  switch(desc[1])
  {
    case 'I':
        width = 4;
        break;
    case 'C':
        width = 2;
        break;
    case 'B':
        width = 1;
        break;
    case 'Z':
        width = 1; /* special-case this? */
        break;
    case 'F':
        width = 4;
        break;
    case 'D':
        width = 8;
        break;
    case 'S':
        width = 2;
        break;
    case 'J':
        width = 8;
        break;
    default:
        width = REF_WIDTH;
  }

  //grabbed it from the AllocArrayObject function in dalvik/vm/oo/Array.c
  size_t objectSize = offsetof(ArrayObject, contents);
  objectSize += o.length * width;

  //I don't know why, but I need this extra 4 bytes - might be because they need to be in an 8 byte boundary for EABI?
  // something like this is mentioned in ArrayObject.h - YES
  objectSize += 4;

  *pObj = (Object*)(malloc(objectSize));
  if (*pObj == NULL)
  {
    free(*pClazz);
    *pClazz = NULL;
    return (OOM_ERROR);
  }

  ret = DECAF_read_mem(env, addr, (void*)(*pObj), objectSize);
  if (ret != 0)
  {
    free(*pObj);
    free(*pClazz);
    *pObj = NULL;
    *pClazz = NULL;
  }

  return (ret);
}


int convertJavaStringToString(CPUState* env, StringObject* pSO, char** pStr)
{
  //first, check parameters
  if ( (pSO == NULL) || (pStr == NULL))
  {
    return (NULL_POINTER_ERROR);
  }

  if ((*pStr != NULL))
  {
    return (NON_NULL_POINTER_ERROR);
  }

  target_ulong addr = (target_ulong)pSO->instanceData[STRING_INDEX_VALUE];
  size_t count = pSO->instanceData[STRING_INDEX_COUNT];

  //now we get the object
  Object* pObj = NULL;
  ClassObject* pClazz = NULL;

  int ret = getObjectAt(env, addr, &pObj, &pClazz);
  if (ret != 0)
  {
    return (-2);
  }

  if (!IS_USERSPACE_ADDR((target_ulong)(pClazz->descriptor)))
  {
    free(pObj);
    pObj = NULL;
    free(pClazz);
    pClazz = NULL;
    return (MEM_READ_ERROR);
  }

  //now this guy should be an array object, so we will have to check that by
  // making sure that the descriptor string is "[C"
  char s[128] = "";
  DECAF_read_mem(env, (target_ulong)pClazz->descriptor, s, 5);
  if ( (s[0] != '[') || (s[1] != 'C') || (s[2] != '\0') )
  {
    free (pObj);
    free (pClazz);
    pObj = NULL;
    pClazz = NULL;
    return (-3);
  }

  //now that we know its a Character Array, lets make sure that the length is greater
  // than or equal to count
  ArrayObject* pAO = (ArrayObject*)(pObj);

  //TODO: this is not necessary since OFFSET might change this a bit
  if ((pAO->length < count))
  {
    free (pObj);
    free (pClazz);
    pObj = NULL;
    pClazz = NULL;
    return (-4);
  }

  *pStr = (char*)(malloc(count + 1));
  if (*pStr == NULL)
  {
    free (pObj);
    free (pClazz);
    pObj = NULL;
    pClazz = NULL;
    return (OOM_ERROR);
  }

  size_t i = 0;
  target_ulong offset = pSO->instanceData[STRING_INDEX_OFFSET];
  char* data = (char*)(pAO->contents);
  data += offset + 4; //TODO:I don't know why, but I need to have this 4 byte offset here. Otherwise, it doesn't work.
  for (; i < count; i++)
  {
    (*pStr)[i] = data[i * 2];
    if ( data[(i * 2) + 1] != 0 ) //check to make sure its ASCII
    {
      free (pObj);
      free (pClazz);
      free (*pStr);
      pObj = NULL;
      pClazz = NULL;
      *pStr = NULL;
      return (-6);
    }
  }
  //end the string properly
  (*pStr)[i] = '\0';

  free (pObj);
  free (pClazz);
  pObj = NULL;
  pClazz = NULL;

  return (0);
}

//just a basic wrapper that uses the other functions
// should be straight forward
int getCStringFromJStringAt(CPUState* env, target_ulong addr, char** pStr)
{
  if (pStr == NULL)
  {
    return (NULL_POINTER_ERROR);
  }
  if (*pStr != NULL)
  {
    return (NON_NULL_POINTER_ERROR);
  }

  Object* pObj = NULL;
  ClassObject* pClazz = NULL;

  int ret = 0;
  ret = getObjectAt(env, addr, &pObj, &pClazz);
  if (ret != 0)
  {
    return (ret + 1000);
  }

  ret = convertJavaStringToString(env, (StringObject*)pObj, pStr);
  free (pObj);
  free (pClazz);
  return (ret);
}

static inline int getClassStringAt(CPUState* env, char* str, size_t len, target_ulong addr)
{
  if (str == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  return (DECAF_read_mem_until(env, addr, str, len));
}

#include "LinuxAPI.h"

int getClassStringFromDexfile(char* str, size_t len, target_ulong addr)
{
  char filename[256];
  filename[0] = '\0';
  target_ulong startAddr = 0;
  target_ulong endAddr = 0;

  if (getModuleInfo(getCurrentPID(), filename, 256, &startAddr, &endAddr, addr) != 0)
  {
    return (-1);
  }

  //now that we have the filename, lets see if we can open it
  char pathname[368];
  snprintf(pathname, 368, "dumps%s", filename);
  printf("trying to open %s\n", pathname);
  FILE* fp = fopen(pathname, "r");
  if (fp == NULL)
  {
    return (FILE_OPEN_ERROR);
  }

  //now that the file is open, calculate the offset
  target_ulong offset = addr - startAddr;
  //now just read in the string from that location
  fseek(fp, offset, SEEK_SET);
  size_t numRead = fread(str, 1, len, fp);
  fclose(fp);
  if (numRead > 0)
  {
    return (0);
  }

  return (-2);
}

static int getClassStringFromMapAt(CPUState* env, TULStrMap* pMap, char* str, size_t len, target_ulong addr)
{
  if (str == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  if (pMap == NULL)
  {
    return (getClassStringAt(env, str, len, addr));
  }

  //pMap and str are not null
  int ret = TULStrMap_getVal(pMap, str, len, addr);

  if (ret == ITEM_NOT_FOUND_ERROR)
  {
    //if its not found, then read it from memory and if it exists, populate it into the map
    ret = getClassStringAt(env, str, len, addr);
    if (ret <= 0)
    {
      //since we can't get it from memory, lets try the file
      if (getClassStringFromDexfile(str, len, addr) < 0)
      {
        //if this fails too, then just fail
        return (-1);
      }
    }
    //since it was successful, update the map
    TULStrMap_add(pMap, addr, str);
  }

  return (ret);
}

int printJavaStringAt(FILE* fp, CPUState* env, gva_t addr)
{
  Object* pObj = NULL;
  ClassObject* pClazz = NULL;

  int ret = 0;
  ret = getObjectAt(env, addr, &pObj, &pClazz);
  if (ret != 0)
  {
    return (ret + 1000);
  }

  char* pStr = NULL;

  //lets see if its a String object if it is then we will convert it to a string
  ret = convertJavaStringToString(env, (StringObject*)pObj, &pStr);
  if (ret == 0)
  {
    DECAF_fprintf(fp, "[%x] \"%s\"\n", addr, pStr);
    free(pObj);
    free(pClazz);
    free(pStr);
    return (0);
  }

  free(pObj);
  free(pClazz);
  return (-1);
}

int printJavaObjectAt(FILE* fp, CPUState* env, target_ulong addr, TULStrMap* pMap)
{
  Object* pObj = NULL;
  ClassObject* pClazz = NULL;
//printf("1\n");
  int ret = 0;
  ret = getObjectAt(env, addr, &pObj, &pClazz);
  if (ret != 0)
  {
    return (ret + 1000);
  }

  char* pStr = NULL;

  //lets see if its a String object if it is then we will convert it to a string
  ret = convertJavaStringToString(env, (StringObject*)pObj, &pStr);
  if (ret == 0)
  {
    DECAF_fprintf(fp, "[%x] \"%s\"\n", addr, pStr);
    free(pObj);
    free(pClazz);
    free(pStr);
    return (0);
  }

  //printf("2\n");
  //we have the object here so lets see how we can get it interpreted
  //to do this we need to grab the ifields array first
  InstField* ifields = malloc(sizeof(InstField) * pClazz->ifieldCount);
  if (ifields == NULL)
  {
    ret = OOM_ERROR;
    goto out;
  }
  //printf("3\n");
  if (DECAF_read_mem(env, (target_ulong)pClazz->ifields, ifields, sizeof(InstField) * pClazz->ifieldCount) != 0)
  {
    free (ifields);
    ret = MEM_READ_ERROR;
    goto out;
  }

  int i = 0;
  int readret = 0;
  char name[128];
  char signature[128];
  JValue val;

  DECAF_fprintf(fp, "Object @ [%x] ... \n", addr);
  for (i = 0; i < pClazz->ifieldCount; i++)
  {
    //printf("4 - %d\n", i);
    //we know that the references come first, so we can just print these
    //first get the name
    //readret = DECAF_read_mem_until((target_ulong)ifields[i].field.name, 128, name);
    readret = getClassStringFromMapAt(env, pMap, name, 128, (target_ulong)ifields[i].field.name);
    if (readret < 0)
    {
      snprintf(name, 127, "?UNKNOWN [%8p]?", ifields[i].field.name);
    }

    //printf("5 - %s\n", name);
    //then the signature
    //readret = DECAF_read_mem_until((target_ulong)ifields[i].field.signature, 128, signature);
    readret = getClassStringFromMapAt(env, pMap, signature, 128, (target_ulong)ifields[i].field.signature);
    if (readret < 0)
    {
      //because it is possible that the memory cannot be read, we will just use a default value
      snprintf(signature, 127, "?[%8p]?", ifields[i].field.signature);
    }
    //make sure its a cstring
    //printf("6 - %s\n", signature);

    //this is kind of dangerous because we could be requesting more than what is available but it should be fine though.
    val = *((JValue*)((void*)pObj + ifields[i].byteOffset) );

    DECAF_fprintf(fp, "  %s (%s) ", name, signature);
    //if its a reference, then its easy
    if (i < pClazz->ifieldRefCount)
    {
      DECAF_fprintf(fp, "@ [%x]\n", val.l); //truncate it
    }
    else
    {
      switch(signature[0])
      {
        case 'B':
          DECAF_fprintf(fp, "= [%x]\n", val.b);
          break;
        case 'Z':
          DECAF_fprintf(fp, "= [%d]\n", val.z);
          break;
        case 'S':
          DECAF_fprintf(fp, "= [%d]\n", val.s);
          break;
        case 'C':
          DECAF_fprintf(fp, "= [%x '%c']\n", val.c, (val.c & 0x7F));
          break;
        case 'F':
          DECAF_fprintf(fp, "= [%e]\n", val.f);
          break;
        case 'I':
          DECAF_fprintf(fp, "= [%d]\n", val.i);
          break;
        default:
          DECAF_fprintf(fp, "@ [%x]\n", val.l);
          break;
        case 'D':
          DECAF_fprintf(fp, "= [%Le]\n", val.d);
          break;
        case 'J':
          DECAF_fprintf(fp, "= [%le]\n", val.j);
          break;
      }
      //we need to switch the signature to see what the size is
    }
  }

  ret = 0;
  free (ifields);

  out:

  free(pObj);
  free(pClazz);
  return (ret);
}

void do_print_object_at(Monitor* mon, target_ulong addr)
{
  printJavaObjectAt(NULL, first_cpu, addr, NULL);
}

#include "dalvik/vm/interp/InterpDefs.h"

target_ulong getDalvikThreadID(CPUState* env, int pid, gva_t pGlue)
{
  //since this is the "glue" structure we first need to get the thread pointer
  //note that the Thread structure has the threadID as the first 4 bytes
  //In the "glue" structure
  target_ulong tid = INV_ADDR;
  target_ulong addr = pGlue + offsetof(InterpState, self);
  target_ulong pThread = INV_ADDR;
  //now get the value
  if (DECAF_read_mem(env, addr, &pThread, 4) == 0)
  {
    //now that we have the thread pointer, lets get the threadID which is just the first 4 bytes
    DECAF_read_mem(env, pThread, &tid, 4);
  }

  return (tid);
}

int getMethodName(CPUState* env, TULStrMap* pMap, target_ulong methodNum, char* str, int len)
{
  if ( (env == NULL) || (str == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  gva_t pDvmDex = INV_ADDR;
  gva_t pResMethod = INV_ADDR;
  gva_t method = INV_ADDR;

  //this procedure pretty much follows invoke-virtual.S
  //get the pDvmDex
  //ldr     r3, [rGLUE, #offGlue_methodClassDex]    @ r3<- pDvmDex
  if (DECAF_read_mem(env, getDalvikGLUE(env) + DS_offGlue_methodClassDex, &pDvmDex, sizeof(gva_t)) != 0)
  {
    return (-1);
  }

  //ldr     r3, [r3, #offDvmDex_pResMethods]    @ r3<- pDvmDex->pResMethods
  //get the pResMethods from pDvmDex
  if (DECAF_read_mem(env, pDvmDex + DS_offDvmDex_pResMethods, &pResMethod, sizeof(gva_t)) != 0)
  {
    return (-2);
  }
  //    FETCH(r1, 1)                        @ r1<- BBBB
  //ldr     r0, [r3, r1, lsl #2]        @ r0<- resolved methodToCall
  if (DECAF_read_mem(env, pResMethod + (methodNum * 4), &method, sizeof(gva_t)) != 0)
  {
    return (-3);
  }

  // if the pointer is NULL then just exit now
  //cmp     r0, #0                      @ already resolved?
  if (method == 0)
  {
    return (-4);
  }

  //since we have the method* now, we can get the insns field first
  gva_t insns = INV_ADDR;
  if (DECAF_read_mem(env, method + DS_offMethod_insns, &insns, sizeof(gva_t)) == 0)
  {
    //if it worked then look up the symbol
    if (getSymbol(str, len, getCurrentPID(), insns) == 0)
    {
      return (0);
    }
  }

  //if we are here then that means we could not get the symbol, in which case
  // lets just see if we can read it from memory and then if not from the dex file
  gva_t name = INV_ADDR;
  if (DECAF_read_mem(env, method + DS_offMethod_name, &name, sizeof(gva_t)) != 0)
  {
    return (-5);
  }

  if (DECAF_read_mem_until(env, name, str, len) <= 0)
  {
    //we couldn't read it from memory so lets finally try to get it from the dex file
    return (getClassStringFromDexfile(str, len, name) + 100);
  }

  return (0);
}

int getMethodNameByVtable(CPUState* env, TULStrMap* pMap, target_ulong objectvregNum, target_ulong methodNum, char* str, int len)
{
  if ( (env == NULL) || (str == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  gva_t objectRef = INV_ADDR;

  if (DECAF_read_mem(env, VREG_TO_GVA(env, objectvregNum), &objectRef, sizeof(gva_t)) != 0)
  {
    return (-1);
  }

  if (objectRef == 0)
  {
    return (-1);
  }

  gva_t class = INV_ADDR;
  gva_t vtable = INV_ADDR;
  gva_t method = INV_ADDR;

  //this is from OP_INVOKE_VIRTUAL_QUICK.S

  //r2 is the objectRef
  //ldr     r2, [r2, #offObject_clazz]  @ r2<- thisPtr->clazz
  if (DECAF_read_mem(env, objectRef + DS_offObject_clazz, &class, sizeof(gva_t)) != 0)
  {
    return (-2);
  }

  //ldr     r2, [r2, #offClassObject_vtable]    @ r2<- thisPtr->clazz->vtable
  if (DECAF_read_mem(env, class + DS_offClassObject_vtable, &vtable, sizeof(gva_t)) != 0)
  {
    return (-3);
  }

  //ldr     r0, [r2, r1, lsl #2]        @ r3<- vtable[BBBB]
  if (DECAF_read_mem(env, vtable + (methodNum * 4), &method, sizeof(gva_t)) != 0)
  {
    return (-4);
  }

  // if the pointer is NULL then just exit now
  //cmp     r0, #0                      @ already resolved?
  if (method == 0)
  {
    return (-5);
  }

  //since we have the method* now, we can get the insns field first
  gva_t insns = INV_ADDR;
  if (DECAF_read_mem(env, method + DS_offMethod_insns, &insns, sizeof(gva_t)) == 0)
  {
    //if it worked then look up the symbol
    if (getSymbol(str, len, getCurrentPID(), insns) == 0)
    {
      return (0);
    }
  }

  //if we are here then that means we could not get the symbol, in which case
  // lets just see if we can read it from memory and then if not from the dex file
  gva_t name = INV_ADDR;
  if (DECAF_read_mem(env, method + DS_offMethod_name, &name, sizeof(gva_t)) != 0)
  {
    return (-6);
  }

  if (DECAF_read_mem_until(env, name, str, len) <= 0)
  {
    //we couldn't read it from memory so lets finally try to get it from the dex file
    return (getClassStringFromDexfile(str, len, name) + 100);
  }

  return (0);
}

int getStaticFieldName(CPUState* env, TULStrMap* pMap, target_ulong fieldNum, char* str, int len)
{
  if ( (env == NULL) || (str == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  gva_t pDvmDex = INV_ADDR;
    gva_t pResFields = INV_ADDR;
    gva_t field = INV_ADDR;

    //this procedure pretty much follows OP_SGET.S
    //get the pDvmDex
    //ldr     r3, [rGLUE, #offGlue_methodClassDex]    @ r3<- pDvmDex
    if (DECAF_read_mem(env, getDalvikGLUE(env) + DS_offGlue_methodClassDex, &pDvmDex, sizeof(gva_t)) != 0)
    {
      return (-1);
    }

    //ldr     r2, [r2, #offDvmDex_pResFields] @ r2<- dvmDex->pResFields
    //get the pResMethods from pDvmDex
    if (DECAF_read_mem(env, pDvmDex + DS_offDvmDex_pResFields, &pResFields, sizeof(gva_t)) != 0)
    {
      return (-2);
    }

    //FETCH(r1, 1)                        @ r1<- BBBB
    //ldr     r0, [r2, r1, lsl #2]        @ r0<- resolved StaticField ptr
    if (DECAF_read_mem(env, pResFields + (fieldNum * 4), &field, sizeof(gva_t)) != 0)
    {
      return (-3);
    }

    // if the pointer is NULL then just exit now
    //cmp     r0, #0                      @ already resolved?
    if (field == 0)
    {
      return (-4);
    }

    //since we have the field* now, we can get the name field
    gva_t name = INV_ADDR;
    if (DECAF_read_mem(env, field + DS_offField_name, &name, sizeof(gva_t)) != 0)
    {
      return (-5);
    }

    if (DECAF_read_mem_until(env, name, str, len) <= 0)
    {
      //we couldn't read it from memory so lets finally try to get it from the dex file
      return (getClassStringFromDexfile(str, len, name) + 100);
    }

    return (0);
}

