/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Dalvik instruction utility functions.
 */
#ifndef _LIBDEX_INSTRUTILS
#define _LIBDEX_INSTRUTILS

#include "DexFile.h"
#include "OpCode.h"

/*
 * Dalvik-defined instruction formats.
 *
 * (This defines InstructionFormat as an unsigned char to reduce the size
 * of the table.  This isn't necessary with some compilers, which use an
 * integer width appropriate for the number of enum values.)
 *
 * If you add or delete a format, you have to change some or all of:
 *  - this enum
 *  - the switch inside dexDecodeInstruction() in InstrUtils.c
 *  - the switch inside dumpInstruction() in DexDump.c
 */
typedef unsigned char InstructionFormat;
enum InstructionFormat {
    kFmtUnknown = 0,
    kFmt10x,        // op
    kFmt12x,        // op vA, vB
    kFmt11n,        // op vA, #+B
    kFmt11x,        // op vAA
    kFmt10t,        // op +AA
    kFmt20bc,       // op AA, thing@BBBB
    kFmt20t,        // op +AAAA
    kFmt22x,        // op vAA, vBBBB
    kFmt21t,        // op vAA, +BBBB
    kFmt21s,        // op vAA, #+BBBB
    kFmt21h,        // op vAA, #+BBBB00000[00000000]
    kFmt21c,        // op vAA, thing@BBBB
    kFmt23x,        // op vAA, vBB, vCC
    kFmt22b,        // op vAA, vBB, #+CC
    kFmt22t,        // op vA, vB, +CCCC
    kFmt22s,        // op vA, vB, #+CCCC
    kFmt22c,        // op vA, vB, thing@CCCC
    kFmt22cs,       // [opt] op vA, vB, field offset CCCC
    kFmt32x,        // op vAAAA, vBBBB
    kFmt30t,        // op +AAAAAAAA
    kFmt31t,        // op vAA, +BBBBBBBB
    kFmt31i,        // op vAA, #+BBBBBBBB
    kFmt31c,        // op vAA, thing@BBBBBBBB
    kFmt35c,        // op {vC, vD, vE, vF, vG}, thing@BBBB (B: count, A: vG)
    kFmt35ms,       // [opt] invoke-virtual+super
    kFmt35fs,       // [opt] invoke-interface
    kFmt3rc,        // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
    kFmt3rms,       // [opt] invoke-virtual+super/range
    kFmt3rfs,       // [opt] invoke-interface/range
    kFmt3inline,    // [opt] inline invoke
    kFmt3rinline,   // [opt] inline invoke/range
    kFmt51l,        // op vAA, #+BBBBBBBBBBBBBBBB
};

/*
 * Holds the contents of a decoded instruction.
 */
#if (0)
typedef struct DecodedInstruction {
    u4      vA;
    u4      vB;
    u8      vB_wide;        /* for kFmt51l */
    u4      vC;
    u4      arg[5];         /* vC/D/E/F/G in invoke or filled-new-array */
    OpCode  opCode;
} DecodedInstruction;
#else
#include <stdint.h>
enum InstructionIndexType{
kIndexUnknown=0,
kIndexNone=1,
kIndexVaries=2,
kIndexTypeRef=3,
kIndexStringRef=4,
kIndexMethodRef=5,
kIndexFieldRef=6,
kIndexInlineMethod=7,
kIndexVtableOffset=8,
kIndexFieldOffset=9,
};

struct DecodedInstruction{
uint32_t vA;
uint32_t vB;
uint64_t vB_wide;
uint32_t vC;
uint32_t arg[5];
enum OpCode opCode;
enum InstructionIndexType indexType;
} __attribute__((packed));
typedef struct DecodedInstruction DecodedInstruction;
#endif
/*
 * Instruction width, a value in the range -3 to 5.
 */
typedef signed char InstructionWidth;

/*
 * Instruction flags, used by the verifier and JIT to determine where
 * control can flow to next.  Expected to fit in 8 bits.
 */
typedef unsigned char InstructionFlags;
enum InstructionFlags {
    kInstrCanBranch     = 1,        // conditional or unconditional branch
    kInstrCanContinue   = 1 << 1,   // flow can continue to next statement
    kInstrCanSwitch     = 1 << 2,   // switch statement
    kInstrCanThrow      = 1 << 3,   // could cause an exception to be thrown
    kInstrCanReturn     = 1 << 4,   // returns, no additional statements
    kInstrInvoke        = 1 << 5,   // a flavor of invoke
    kInstrUnconditional = 1 << 6,   // unconditional branch
};


/*
 * Allocate and populate a 256-element array with instruction widths.  A
 * width of zero means the entry does not exist.
 */
InstructionWidth* dexCreateInstrWidthTable(void);

#if 0       // no longer used
/*
 * Returns the width of the specified instruction, or 0 if not defined.
 * Optimized instructions use negative values.
 */
DEX_INLINE int dexGetInstrWidth(const InstructionWidth* widths, OpCode opCode)
{
   // assert(/*opCode >= 0 &&*/ opCode < kNumDalvikInstructions);
    return widths[opCode];
}
#endif

/*
 * Return the width of the specified instruction, or 0 if not defined.
 */
DEX_INLINE size_t dexGetInstrWidthAbs(const InstructionWidth* widths,
    OpCode opCode)
{
    //assert(/*opCode >= 0 &&*/ opCode < kNumDalvikInstructions);

    int val = widths[opCode];
    if (val < 0)
        val = -val;
    /* XXX - the no-compare trick may be a cycle slower on ARM */
    return val;
}

/*
 * Return the width of the specified instruction, or 0 if not defined.  Also
 * works for special OP_NOP entries, including switch statement data tables
 * and array data.
 */
size_t dexGetInstrOrTableWidthAbs(const InstructionWidth* widths,
    const u2* insns);


/*
 * Allocate and populate a 256-element array with instruction flags.
 */
InstructionFlags* dexCreateInstrFlagsTable(void);

/*
 * Returns the flags for the specified opcode.
 */
DEX_INLINE int dexGetInstrFlags(const InstructionFlags* flags, OpCode opCode)
{
    //assert(/*opCode >= 0 &&*/ opCode < kNumDalvikInstructions);
    return flags[opCode];
}


/*
 * Allocate and populate a 256-element array with instruction formats.
 */
InstructionFormat* dexCreateInstrFormatTable(void);

/*
 * Return the instruction format for the specified opcode.
 */
DEX_INLINE InstructionFormat dexGetInstrFormat(const InstructionFormat* fmts,
    OpCode opCode)
{
    //assert(/*opCode >= 0 &&*/ opCode < kNumDalvikInstructions);
    return fmts[opCode];
}

/*
 * Decode the instruction pointed to by "insns".
 */
void dexDecodeInstruction(const InstructionFormat* fmts, const u2* insns,
    DecodedInstruction* pDec);

#endif /*_LIBDEX_INSTRUTILS*/
