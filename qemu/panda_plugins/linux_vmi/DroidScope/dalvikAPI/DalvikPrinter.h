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

/*
 * DalvikPrinter.h
 *
 *  Created on: May 22, 2012
 *      Author: lok
 */

#ifndef DALVIKPRINTER_H_
#define DALVIKPRINTER_H_

#include "DECAF_shared/DECAF_types.h"

#ifdef __cplusplus
extern "C"
{
#include "dalvik/libdex/OpCode.h"
  struct DecodedInstruction {
      u4      vA;
      u4      vB;
      u8      vB_wide;        /* for kFmt51l */
      u4      vC;
      u4      arg[5];         /* vC/D/E/F/G in invoke or filled-new-array */
      OpCode  opCode;
  };
#else
#include "dalvik/libdex/InstrUtils.h"
#endif


typedef enum
{
  DALVIK_TYPE_NULL, // == default for none
  DALVIK_TYPE_INT,// = 4,
  DALVIK_TYPE_CHAR,// = 2,
  DALVIK_TYPE_BYTE,// = 1,
  DALVIK_TYPE_BOOLEAN,// = 1,
  DALVIK_TYPE_FLOAT,// = 4,
  DALVIK_TYPE_DOUBLE,// = 8,
  DALVIK_TYPE_SHORT,// = 2,
  DALVIK_TYPE_LONG,// = 8,
  DALVIK_TYPE_REF,// = 4
  DALVIK_TYPE_RAW_8, // = 1 byte - generic type
  DALVIK_TYPE_RAW_16, // = 2
  DALVIK_TYPE_RAW_32, // = 4
  DALVIK_TYPE_RAW_64, // = 8
  //THE FOLLOWING TYPES SHOULD NOT BE USED BY THE PRINTER - ITS NOT FOR REGISTERS
  DALVIK_TYPE_CONST_S_4, // = const 4 bits treated as a signed int
  DALVIK_TYPE_CONST_S_8, // = const 8 bits treated as a signed int
  DALVIK_TYPE_CONST_S_16, // = const 16 bits treated as a signed int
  DALVIK_TYPE_CONST_S_32, // = const 32 bits treated as a signed int
  DALVIK_TYPE_CONST_RAW_4, // = const 4 bits
  DALVIK_TYPE_CONST_RAW_8, // = const 8 bits
  DALVIK_TYPE_CONST_RAW_16, // = const 16 bits
  DALVIK_TYPE_CONST_RAW_32, // = const 32 bits
  DALVIK_TYPE_CONST_RAW_64 // const 64 bits
} OperandTypes;

void printDalvikRegister(FILE* outputfp, CPUState* env, u4 vreg, OperandTypes type);

void dumpDalvikInstruction(FILE* outputfp, CPUState* env, const u2* insns, int insnIdx, int insnWidth,
    const DecodedInstruction* pDecInsn, uint32_t methodAddress, uint32_t address, LogLevel eLogLevel);

int getDalvikInstruction(CPUState* env, uint32_t rpc, int* pWidth, u2* pInsns, int len);
void decodeDalvikInstruction(const u2* pInsns, DecodedInstruction* pDecInsn);

#ifdef __cplusplus
}
#endif

#endif /* DALVIKPRINTER_H_ */
