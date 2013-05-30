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
 * @date 1/30/2012
 */
#ifndef ANDROID_HELPER_FUNCTIONS_H
#define ANDROID_HELPER_FUNCTIONS_H

#include "DECAF_shared/DECAF_types.h"
#include "DECAF_shared/utils/TULStringMapWrapper.h"

int getMethodName(CPUState* env, TULStrMap* pMap, target_ulong methodNum, char* str, size_t len);
int getMethodNameByVtable(CPUState* env, TULStrMap* pMap, gva_t objectRef, target_ulong methodNum, char* str, size_t len);

int getStaticFieldName(CPUState* env, TULStrMap* pMap, target_ulong fieldNum, char* str, size_t len);
int getClassStringFromMapAt(TULStrMap* pMap, char* str, size_t len, target_ulong addr);
//int printDalvikMethodPrototypeAtBeginning(FILE* fp, CPUState* env, int pid, gva_t addr, gva_t callerRPC, U32StrMap* classStrings);

#endif//ANDROID_HELPER_FUNCTIONS_H
