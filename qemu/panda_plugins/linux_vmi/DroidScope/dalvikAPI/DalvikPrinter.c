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
 * @file DalvikInstructionTrace.c
 *   Implements a Dalvik instruction tracer. Only uses the DalvikMterpOpcodes callback.
 * @author Lok Yan
 * @date 1/6/2012
 */

#include "DalvikAPI.h"
#include "dalvikAPI/DalvikPrinter.h"
#include "dalvikAPI/DalvikConstants.h"
#include "dalvikAPI/DalvikOpcodeTable.h"
#include "dalvikAPI/AndroidHelperFunctions.h"
#include "dalvik/libdex/DexFile.h"
#include "dalvik/libdex/DexProto.h"
#include "dalvik/libdex/InstrUtils.h"

#include "DECAF_shared/utils/OutputWrapper.h"
//#include "DECAF_shared/DECAF_main.h"

/**************************
 * THIS WHOLE SECTION IS STOLEN FROM DexDump.c in the dalvik/dexdump directory
 * Just made a few changes to make it work for me thats about it.
 */

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
 * The "dexdump" tool is intended to mimic "objdump".  When possible, use
 * similar command-line arguments.
 *
 * TODO: rework the "plain" output format to be more regexp-friendly
 *
 * Differences between XML output and the "current.xml" file:
 * - classes in same package are not all grouped together; generally speaking
 *   nothing is sorted
 * - no "deprecated" on fields and methods
 * - no "value" on fields
 * - no parameter names
 * - no generic signatures on parameters, e.g. type="java.lang.Class&lt;?&gt;"
 * - class shows declared fields and methods; does not show inherited fields
 */

/*
#include "libdex/DexCatch.h"
#include "libdex/DexClass.h"


#include "libdex/OpCodeNames.h"
#include "libdex/SysUtil.h"
#include "libdex/CmdUtils.h"
*/

#include <string.h>

//LOK - to get the u... definitions
#include "dalvik/vm/Common.h"

static InstructionWidth* gInstrWidth = NULL;
static InstructionFormat* gInstrFormat = NULL;

/* basic info about a field or method */
typedef struct FieldMethodInfo {
    const char* classDescriptor;
    const char* name;
    const char* signature;
} FieldMethodInfo;

/*
 * Get 2 little-endian bytes.
 */
static inline u2 get2LE(unsigned char const* pSrc)
{
    return pSrc[0] | (pSrc[1] << 8);
}

/*
 * Get 4 little-endian bytes.
 */
static inline u4 get4LE(unsigned char const* pSrc)
{
    return pSrc[0] | (pSrc[1] << 8) | (pSrc[2] << 16) | (pSrc[3] << 24);
}

#if 0 //NOT USED

/*
 * Converts a single-character primitive type into its human-readable
 * equivalent.
 */
static const char* primitiveTypeLabel(char typeChar)
{
    switch (typeChar) {
    case 'B':   return "byte";
    case 'C':   return "char";
    case 'D':   return "double";
    case 'F':   return "float";
    case 'I':   return "int";
    case 'J':   return "long";
    case 'S':   return "short";
    case 'V':   return "void";
    case 'Z':   return "boolean";
    default:
                return "UNKNOWN";
    }
}

/*
 * Converts a type descriptor to human-readable "dotted" form.  For
 * example, "Ljava/lang/String;" becomes "java.lang.String", and
 * "[I" becomes "int[]".  Also converts '$' to '.', which means this
 * form can't be converted back to a descriptor.
 */
static char* descriptorToDot(const char* str)
{
    int targetLen = strlen(str);
    int offset = 0;
    int arrayDepth = 0;
    char* newStr;

    /* strip leading [s; will be added to end */
    while (targetLen > 1 && str[offset] == '[') {
        offset++;
        targetLen--;
    }
    arrayDepth = offset;

    if (targetLen == 1) {
        /* primitive type */
        str = primitiveTypeLabel(str[offset]);
        offset = 0;
        targetLen = strlen(str);
    } else {
        /* account for leading 'L' and trailing ';' */
        if (targetLen >= 2 && str[offset] == 'L' &&
            str[offset+targetLen-1] == ';')
        {
            targetLen -= 2;
            offset++;
        }
    }

    newStr = malloc(targetLen + arrayDepth * 2 +1);

    /* copy class name over */
    int i;
    for (i = 0; i < targetLen; i++) {
        char ch = str[offset + i];
        newStr[i] = (ch == '/' || ch == '$') ? '.' : ch;
    }

    /* add the appropriate number of brackets for arrays */
    while (arrayDepth-- > 0) {
        newStr[i++] = '[';
        newStr[i++] = ']';
    }
    newStr[i] = '\0';
    assert(i == targetLen + arrayDepth * 2);

    return newStr;
}

/*
 * Converts the class name portion of a type descriptor to human-readable
 * "dotted" form.
 *
 * Returns a newly-allocated string.
 */
static char* descriptorClassToDot(const char* str)
{
    const char* lastSlash;
    char* newStr;
    char* cp;

    /* reduce to just the class name, trimming trailing ';' */
    lastSlash = strrchr(str, '/');
    if (lastSlash == NULL)
        lastSlash = str + 1;        /* start past 'L' */
    else
        lastSlash++;                /* start past '/' */

    newStr = strdup(lastSlash);
    newStr[strlen(lastSlash)-1] = '\0';
    for (cp = newStr; *cp != '\0'; cp++) {
        if (*cp == '$')
            *cp = '.';
    }

    return newStr;
}

/*
 * Returns a quoted string representing the boolean value.
 */
static const char* quotedBool(bool val)
{
    if (val)
        return "\"true\"";
    else
        return "\"false\"";
}

static const char* quotedVisibility(u4 accessFlags)
{
    if ((accessFlags & ACC_PUBLIC) != 0)
        return "\"public\"";
    else if ((accessFlags & ACC_PROTECTED) != 0)
        return "\"protected\"";
    else if ((accessFlags & ACC_PRIVATE) != 0)
        return "\"private\"";
    else
        return "\"package\"";
}

/*
 * Count the number of '1' bits in a word.
 */
static int countOnes(u4 val)
{
    int count = 0;

    val = val - ((val >> 1) & 0x55555555);
    val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
    count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;

    return count;
}


/*
 * Flag for use with createAccessFlagStr().
 */
typedef enum AccessFor {
    kAccessForClass = 0, kAccessForMethod = 1, kAccessForField = 2,
    kAccessForMAX
} AccessFor;

/*
 * Create a new string with human-readable access flags.
 *
 * In the base language the access_flags fields are type u2; in Dalvik
 * they're u4.
 */
static char* createAccessFlagStr(u4 flags, AccessFor forWhat)
{
#define NUM_FLAGS   18
    static const char* kAccessStrings[kAccessForMAX][NUM_FLAGS] = {
        {
            /* class, inner class */
            "PUBLIC",           /* 0x0001 */
            "PRIVATE",          /* 0x0002 */
            "PROTECTED",        /* 0x0004 */
            "STATIC",           /* 0x0008 */
            "FINAL",            /* 0x0010 */
            "?",                /* 0x0020 */
            "?",                /* 0x0040 */
            "?",                /* 0x0080 */
            "?",                /* 0x0100 */
            "INTERFACE",        /* 0x0200 */
            "ABSTRACT",         /* 0x0400 */
            "?",                /* 0x0800 */
            "SYNTHETIC",        /* 0x1000 */
            "ANNOTATION",       /* 0x2000 */
            "ENUM",             /* 0x4000 */
            "?",                /* 0x8000 */
            "VERIFIED",         /* 0x10000 */
            "OPTIMIZED",        /* 0x20000 */
        },
        {
            /* method */
            "PUBLIC",           /* 0x0001 */
            "PRIVATE",          /* 0x0002 */
            "PROTECTED",        /* 0x0004 */
            "STATIC",           /* 0x0008 */
            "FINAL",            /* 0x0010 */
            "SYNCHRONIZED",     /* 0x0020 */
            "BRIDGE",           /* 0x0040 */
            "VARARGS",          /* 0x0080 */
            "NATIVE",           /* 0x0100 */
            "?",                /* 0x0200 */
            "ABSTRACT",         /* 0x0400 */
            "STRICT",           /* 0x0800 */
            "SYNTHETIC",        /* 0x1000 */
            "?",                /* 0x2000 */
            "?",                /* 0x4000 */
            "MIRANDA",          /* 0x8000 */
            "CONSTRUCTOR",      /* 0x10000 */
            "DECLARED_SYNCHRONIZED", /* 0x20000 */
        },
        {
            /* field */
            "PUBLIC",           /* 0x0001 */
            "PRIVATE",          /* 0x0002 */
            "PROTECTED",        /* 0x0004 */
            "STATIC",           /* 0x0008 */
            "FINAL",            /* 0x0010 */
            "?",                /* 0x0020 */
            "VOLATILE",         /* 0x0040 */
            "TRANSIENT",        /* 0x0080 */
            "?",                /* 0x0100 */
            "?",                /* 0x0200 */
            "?",                /* 0x0400 */
            "?",                /* 0x0800 */
            "SYNTHETIC",        /* 0x1000 */
            "?",                /* 0x2000 */
            "ENUM",             /* 0x4000 */
            "?",                /* 0x8000 */
            "?",                /* 0x10000 */
            "?",                /* 0x20000 */
        },
    };
    const int kLongest = 21;        /* strlen of longest string above */
    int i, count;
    char* str;
    char* cp;

    /*
     * Allocate enough storage to hold the expected number of strings,
     * plus a space between each.  We over-allocate, using the longest
     * string above as the base metric.
     */
    count = countOnes(flags);
    cp = str = (char*) malloc(count * (kLongest+1) +1);

    for (i = 0; i < NUM_FLAGS; i++) {
        if (flags & 0x01) {
            const char* accessStr = kAccessStrings[forWhat][i];
            int len = strlen(accessStr);
            if (cp != str)
                *cp++ = ' ';

            memcpy(cp, accessStr, len);
            cp += len;
        }
        flags >>= 1;
    }
    *cp = '\0';

    return str;
}


/*
 * Copy character data from "data" to "out", converting non-ASCII values
 * to printf format chars or an ASCII filler ('.' or '?').
 *
 * The output buffer must be able to hold (2*len)+1 bytes.  The result is
 * NUL-terminated.
 */
static void asciify(char* out, const unsigned char* data, size_t len)
{
    while (len--) {
        if (*data < 0x20) {
            /* could do more here, but we don't need them yet */
            switch (*data) {
            case '\0':
                *out++ = '\\';
                *out++ = '0';
                break;
            case '\n':
                *out++ = '\\';
                *out++ = 'n';
                break;
            default:
                *out++ = '.';
                break;
            }
        } else if (*data >= 0x80) {
            *out++ = '?';
        } else {
            *out++ = *data;
        }
        data++;
    }
    *out = '\0';
}
#endif // NOT USED

//stores the number of bytes that are to be used up with the index as the opcode
//these are the operand sizes so they can be printed out properly
static OperandTypes operandTypeTable[256][3] = {
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 0 "nop",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_NULL }, // 1     "move",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_NULL }, // 2     "move/from16",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_NULL }, // 3     "move/16",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_NULL }, // 4     "move-wide",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_NULL }, // 5     "move-wide/from16",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_NULL }, // 6     "move-wide/16",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL }, // 7     "move-object",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL }, // 8     "move-object/from16",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL }, // 9     "move-object/16",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // A     "move-result",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // B     "move-result-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // C     "move-result-object",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // D     "move-exception",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E     "return-void",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F     "return",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 10     "return-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 11     "return-object",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_4 ,  DALVIK_TYPE_NULL }, // 12     "const/4",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 ,  DALVIK_TYPE_NULL }, // 13     "const/16",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_32 ,  DALVIK_TYPE_NULL }, // 14     "const",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 ,  DALVIK_TYPE_NULL }, // 15     "const/high16",
    { DALVIK_TYPE_LONG ,  DALVIK_TYPE_CONST_S_16 ,  DALVIK_TYPE_NULL }, // 16     "const-wide/16",
    { DALVIK_TYPE_LONG ,  DALVIK_TYPE_CONST_S_32 ,  DALVIK_TYPE_NULL }, // 17     "const-wide/32",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_CONST_RAW_64 ,  DALVIK_TYPE_NULL }, // 18     "const-wide",
    { DALVIK_TYPE_LONG ,  DALVIK_TYPE_CONST_S_16 ,  DALVIK_TYPE_NULL }, // 19     "const-wide/high16",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 1A     "const-string",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_32 ,  DALVIK_TYPE_NULL }, // 1B     "const-string/jumbo",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 1C     "const-class",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 1D     "monitor-enter",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 1E     "monitor-exit",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 1F     "check-cast",
    { DALVIK_TYPE_BOOLEAN ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 20     "instance-of",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL }, // 21     "array-length",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 22     "new-instance",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_RAW_16 }, // 23     "new-array",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 24     "filled-new-array", FIXME
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 25     "filled-new-array/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 26     "fill-array-data",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 27     "throw",
    { DALVIK_TYPE_CONST_S_8 ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 28     "goto",
    { DALVIK_TYPE_CONST_S_16 ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 29     "goto/16",
    { DALVIK_TYPE_CONST_S_32 ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 2A     "goto/32",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_S_32 ,  DALVIK_TYPE_NULL }, // 2B     "packed-switch",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_S_32 ,  DALVIK_TYPE_NULL }, // 2C     "sparse-switch",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_FLOAT }, // 2D     "cmpl-float",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_FLOAT }, // 2E     "cmpg-float",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE }, // 2F     "cmpl-double",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE }, // 30     "cmpg-double",
    { DALVIK_TYPE_INT ,  DALVIK_TYPE_LONG ,  DALVIK_TYPE_LONG }, // 31     "cmp-long",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 }, // 32     "if-eq",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 }, // 33     "if-ne",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 }, // 34     "if-lt",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 }, // 35     "if-ge",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 }, // 36     "if-gt",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 }, // 37     "if-le",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 38     "if-eqz",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 39     "if-nez",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 3A     "if-ltz",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 3B     "if-gez",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 3C     "if-gtz",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 3D     "if-lez",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 3E     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 3F     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 40     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 41     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 42     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 43     "UNUSED",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 44     "aget",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 45     "aget-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 46     "aget-object",
    { DALVIK_TYPE_BOOLEAN ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 47     "aget-boolean",
    { DALVIK_TYPE_BYTE ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 48     "aget-byte",
    { DALVIK_TYPE_CHAR ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 49     "aget-char",
    { DALVIK_TYPE_SHORT ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 4A     "aget-short",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 4B     "aput",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 4C     "aput-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 4D     "aput-object",
    { DALVIK_TYPE_BOOLEAN ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 4E     "aput-boolean",
    { DALVIK_TYPE_BYTE ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 4F     "aput-byte",
    { DALVIK_TYPE_CHAR ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 50     "aput-char",
    { DALVIK_TYPE_SHORT ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_INT }, // 51     "aput-short",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 52     "iget",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 53     "iget-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 54     "iget-object",
    { DALVIK_TYPE_BOOLEAN ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 55     "iget-boolean",
    { DALVIK_TYPE_BYTE ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 56     "iget-byte",
    { DALVIK_TYPE_CHAR ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 57     "iget-char",
    { DALVIK_TYPE_SHORT ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 58     "iget-short",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 59     "iput",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 5A     "iput-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 5B     "iput-object",
    { DALVIK_TYPE_BOOLEAN ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 5C     "iput-boolean",
    { DALVIK_TYPE_BYTE ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 5D     "iput-byte",
    { DALVIK_TYPE_CHAR ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 5E     "iput-char",
    { DALVIK_TYPE_SHORT ,  DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 }, // 5F     "iput-short",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 60     "sget",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 61     "sget-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 62     "sget-object",
    { DALVIK_TYPE_BOOLEAN ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 63     "sget-boolean",
    { DALVIK_TYPE_BYTE ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 64     "sget-byte",
    { DALVIK_TYPE_CHAR ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 65     "sget-char",
    { DALVIK_TYPE_SHORT ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 66     "sget-short",
    { DALVIK_TYPE_RAW_32 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 67     "sput",
    { DALVIK_TYPE_RAW_64 ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 68     "sput-wide",
    { DALVIK_TYPE_REF ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 69     "sput-object",
    { DALVIK_TYPE_BOOLEAN ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 6A     "sput-boolean",
    { DALVIK_TYPE_BYTE ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 6B     "sput-byte",
    { DALVIK_TYPE_CHAR ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 6C     "sput-char",
    { DALVIK_TYPE_SHORT ,  DALVIK_TYPE_CONST_RAW_16 ,  DALVIK_TYPE_NULL }, // 6D     "sput-short",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 6E     "invoke-virtual", FIXME
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 6F     "invoke-super",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 70     "invoke-direct",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 71     "invoke-static",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 72     "invoke-interface",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 73     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 74     "invoke-virtual/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 75     "invoke-super/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 76     "invoke-direct/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 77     "invoke-static/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 78     "invoke-interface/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 79     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // 7A     "UNUSED",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 7B     "neg-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 7C     "not-int",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // 7D     "neg-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // 7E     "not-long",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // 7F     "neg-float",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // 80     "neg-double",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 81     "int-to-long",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 82     "int-to-float",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 83     "int-to-double",
    { DALVIK_TYPE_INT , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // 84     "long-to-int",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // 85     "long-to-float",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // 86     "long-to-double",
    { DALVIK_TYPE_INT , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // 87     "float-to-int",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // 88     "float-to-long",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // 89     "float-to-double",
    { DALVIK_TYPE_INT , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // 8A     "double-to-int",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // 8B     "double-to-long",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // 8C     "double-to-float",
    { DALVIK_TYPE_BYTE , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 8D     "int-to-byte",
    { DALVIK_TYPE_CHAR , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 8E     "int-to-char",
    { DALVIK_TYPE_SHORT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // 8F     "int-to-short",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 90     "add-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 91     "sub-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 92     "mul-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 93     "div-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 94     "rem-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 95     "and-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 96     "or-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 97     "xor-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 98     "shl-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 99     "shr-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT , DALVIK_TYPE_INT }, // 9A     "ushr-int",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // 9B     "add-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // 9C     "sub-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // 9D     "mul-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // 9E     "div-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // 9F     "rem-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // A0     "and-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // A1     "or-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // A2     "xor-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // A3     "shl-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // A4     "shr-long",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG , DALVIK_TYPE_LONG }, // A5     "ushr-long",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT }, // A6     "add-float",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT }, // A7     "sub-float",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT }, // A8     "mul-float",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT }, // A9     "div-float",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT }, // AA     "rem-float",
    {  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE }, // AB     "add-double",
    {  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE }, // AC     "sub-double",
    {  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE }, // AD     "mul-double",
    {  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE }, // AE     "div-double",
    {  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_DOUBLE }, // AF     "rem-double",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B0     "add-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B1     "sub-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B2     "mul-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B3     "div-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B4     "rem-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B5     "and-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B6     "or-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B7     "xor-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B8     "shl-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // B9     "shr-int/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_NULL }, // BA     "ushr-int/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // BB     "add-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // BC     "sub-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // BD     "mul-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // BE     "div-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // BF     "rem-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // C0     "and-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // C1     "or-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // C2     "xor-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // C3     "shl-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // C4     "shr-long/2addr",
    { DALVIK_TYPE_LONG , DALVIK_TYPE_LONG ,  DALVIK_TYPE_NULL }, // C5     "ushr-long/2addr",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // C6     "add-float/2addr",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // C7     "sub-float/2addr",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // C8     "mul-float/2addr",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // C9     "div-float/2addr",
    { DALVIK_TYPE_FLOAT , DALVIK_TYPE_FLOAT ,  DALVIK_TYPE_NULL }, // CA     "rem-float/2addr",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // CB     "add-double/2addr",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // CC     "sub-double/2addr",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // CD     "mul-double/2addr",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // CE     "div-double/2addr",
    { DALVIK_TYPE_DOUBLE , DALVIK_TYPE_DOUBLE ,  DALVIK_TYPE_NULL }, // CF     "rem-double/2addr",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D0     "add-int/lit16",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D1     "rsub-int",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D2     "mul-int/lit16",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D3     "div-int/lit16",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D4     "rem-int/lit16",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D5     "and-int/lit16",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D6     "or-int/lit16",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_16 }, // D7     "xor-int/lit16",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // D8     "add-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // D9     "rsub-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // DA     "mul-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // DB     "div-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // DC     "rem-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // DD     "and-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // DE     "or-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // DF     "xor-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // E0     "shl-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // E1     "shr-int/lit8",
    { DALVIK_TYPE_INT , DALVIK_TYPE_INT ,  DALVIK_TYPE_CONST_S_8 }, // E2     "ushr-int/lit8",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E3     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E4     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E5     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E6     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E7     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E8     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // E9     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // EA     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // EB     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // EC     "^breakpoint",                  // does not appear in DEX files FIXME
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // ED     "^throw-verification-error",    // does not appear in DEX files
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // EE     "+execute-inline",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // EF     "+execute-inline/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F0     "+invoke-direct-empty",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F1     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F2     "+iget-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F3     "+iget-wide-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F4     "+iget-object-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F5     "+iput-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F6     "+iput-wide-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F7     "+iput-object-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F8     "+invoke-virtual-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // F9     "+invoke-virtual-quick/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // FA     "+invoke-super-quick",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // FB     "+invoke-super-quick/range",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // FC     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // FD     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // FE     "UNUSED",
    { DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL ,  DALVIK_TYPE_NULL }, // FF     "UNUSED",

};

void printDalvikRegister(FILE* outputfp, CPUState* env, u4 vreg, OperandTypes type)
{
  u1 vrVal_1;
  u2 vrVal_2;
  u4 vrVal_4;
  u8 vrVal_8;
  s8 vrVal_s8;

  switch(type)
  {
    case DALVIK_TYPE_CHAR :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_2, sizeof(u2));
      DECAF_fprintf(outputfp, "%c(%02x)", (char)vrVal_2 & 0xFF, vrVal_2);
      break;
    }
    case DALVIK_TYPE_BYTE :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_1, sizeof(u1));
      DECAF_fprintf(outputfp, "%02x", vrVal_1);
      break;
    }
    case DALVIK_TYPE_BOOLEAN :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_1, sizeof(u1));
      DECAF_fprintf(outputfp, "%c", vrVal_1 ? 'T' : 'F');
      break;
    }
    case DALVIK_TYPE_FLOAT :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_4, sizeof(u4));
      DECAF_fprintf(outputfp,"%E",vrVal_4);
      break;
    }
    case DALVIK_TYPE_DOUBLE :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_s8, sizeof(s8));
      DECAF_fprintf(outputfp,"%llE",vrVal_s8);
      break;
    }
    case DALVIK_TYPE_INT :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_4, sizeof(u4));
      DECAF_fprintf(outputfp,"%d",vrVal_4);
      break;
    }
    case DALVIK_TYPE_SHORT :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_2, sizeof(u2));
      DECAF_fprintf(outputfp,"%d",vrVal_2);
      break;
    }
    case DALVIK_TYPE_LONG :
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_8, sizeof(u8));
      DECAF_fprintf(outputfp,"%lld",vrVal_8);
      break;
    }
    case DALVIK_TYPE_REF:
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_4, sizeof(u4));
      DECAF_fprintf(outputfp,"0x%08x",vrVal_4);
      break;
    }
    case DALVIK_TYPE_RAW_8:
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_1, sizeof(u1));
      DECAF_fprintf(outputfp,"0x%02x",vrVal_1);
      break;
    }
    case DALVIK_TYPE_RAW_16:
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_2, sizeof(u2));
      DECAF_fprintf(outputfp,"0x%04x",vrVal_2);
      break;
    }
    default:
    case DALVIK_TYPE_RAW_32:
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_4, sizeof(u4));
      DECAF_fprintf(outputfp,"0x%08x",vrVal_4);
      break;
    }
    case DALVIK_TYPE_RAW_64:
    {
      DECAF_read_mem(env, VREG_TO_GVA(env, vreg), &vrVal_8, sizeof(u8));
      DECAF_fprintf(outputfp,"0x%16llx",vrVal_8);
      break;
    }
  }
}

/*
 * Dump a single instruction.
 * TODO: I should really create a different copy of this to check and process the taints
 */
void dumpDalvikInstruction(FILE* outputfp, CPUState* env, const u2* insns, int insnIdx, int insnWidth,
    const DecodedInstruction* pDecInsn, uint32_t methodAddress, uint32_t address, LogLevel eLogLevel)
{
  int i;
  char methodName[128];
  u4 vr_ival1;
  DECAF_fprintf(outputfp,"[%08x]  ", address);

  if ( (gInstrWidth == NULL) || (gInstrFormat == NULL) )
  {
    return;
  }

  for (i = 0; i < 8; i++) {
      if (i < insnWidth) {
          if (i == 7) {
              DECAF_fprintf(outputfp," ... ");
          } else {
              /* print 16-bit value in little-endian order */
              const u1* bytePtr = (const u1*) &insns[insnIdx+i];
              DECAF_fprintf(outputfp," %02x%02x", bytePtr[0], bytePtr[1]);
          }
      } else {
          DECAF_fprintf(outputfp, "     ");
      }
  }

  if (pDecInsn->opCode == OP_NOP) {
      u2 instr = get2LE((const u1*) &insns[insnIdx]);
      if (instr == kPackedSwitchSignature) {
          DECAF_fprintf(outputfp,"|%04x: packed-switch-data (%d units)",
              //insnIdx, insnWidth);
              address - methodAddress, insnWidth);
      } else if (instr == kSparseSwitchSignature) {
          DECAF_fprintf(outputfp,"|%04x: sparse-switch-data (%d units)",
              //insnIdx, insnWidth);
              address - methodAddress, insnWidth);
      } else if (instr == kArrayDataSignature) {
          DECAF_fprintf(outputfp,"|%04x: array-data (%d units)",
              //insnIdx, insnWidth);
              address - methodAddress, insnWidth);
      } else {
          //DECAF_fprintf(outputfp,"|%04x: nop // spacer", insnIdx);
        DECAF_fprintf(outputfp,"|%04x: nop // spacer", (address - methodAddress));
      }
  } else {
      //DECAF_fprintf(outputfp,"|%04x: %s", insnIdx, dalvikOpcodeToString(pDecInsn->opCode));
    DECAF_fprintf(outputfp,"|%04x: %s", address - methodAddress, dalvikOpcodeToString(pDecInsn->opCode));
  }

    switch (dexGetInstrFormat(gInstrFormat, pDecInsn->opCode)) {
    case kFmt10x:        // op
        break;
    case kFmt12x:        // op vA, vB
        DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA,operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vB);
        printDalvikRegister(outputfp, env,pDecInsn->vB,operandTypeTable[pDecInsn->opCode][1]);
        DECAF_fprintf(outputfp,")");
        //DECAF_fprintf(outputfp," v%d(%016llx), v%d(%016llx)", pDecInsn->vA, vr_dval1, pDecInsn->vB, vr_dval2);
        break;
    case kFmt11n:        // op vA, #+B
        DECAF_fprintf(outputfp, " v%d(",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA,operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp, "), #int ");
        printDalvikRegister(outputfp, env,pDecInsn->vB,operandTypeTable[pDecInsn->opCode][1]);
        //DECAF_fprintf(outputfp," v%d(%08x), #int %d // #%x",
        //    pDecInsn->vA, vr_ival1,(s4)pDecInsn->vB, (u1)pDecInsn->vB);
        break;
    case kFmt11x:        // op vAA
        DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp, ")");

        //add in support to print out the object if its move-result object or whatever
        if (pDecInsn->opCode == OP_MOVE_RESULT_OBJECT)
        {
          if (eLogLevel >= LOG_LEVEL_EVERYTHING)
          {
            gva_t resultAddr = 0;
            DECAF_read_mem(env, getDalvikGLUE(env) + DS_offGlue_retval, &resultAddr, sizeof(gva_t));
            printJavaObjectAt(outputfp, env, resultAddr, NULL);
          }
        }
        //DECAF_fprintf(outputfp," v%d",pDecInsn->vA);
        break;
    case kFmt10t:        // op +AA
    case kFmt20t:        // op +AAAA
        {
            s4 targ = (s4) pDecInsn->vA;
            DECAF_fprintf(outputfp," %04x // %c%04x",
                //insnIdx + targ,
                (address - methodAddress) + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        }
        break;
    case kFmt22x:        // op vAA, vBBBB
        DECAF_fprintf(outputfp," v%d(", pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp,"),  v%d(",pDecInsn->vB);
        printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
        //DECAF_fprintf(outputfp," v%d, v%d", pDecInsn->vA, pDecInsn->vB);
        break;
    case kFmt21t:        // op vAA, +BBBB
        {
            s4 targ = (s4) pDecInsn->vB;
            DECAF_fprintf(outputfp," v%d(", pDecInsn->vA);
            printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
            DECAF_fprintf(outputfp,"), %04x // %c%04x",
                //insnIdx + targ,
                (address - methodAddress) + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        }
        break;
    case kFmt21s:        // op vAA, #+BBBB
        DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA,operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp,"), #int ");
        printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
        /*DECAF_fprintf(outputfp," v%d (eknath6), #int %d // #%x",
            pDecInsn->vA, (s4)pDecInsn->vB, (u2)pDecInsn->vB);*/
        break;
    case kFmt21h:        // op vAA, #+BBBB0000[00000000]
        // The printed format varies a bit based on the actual opcode.
        DECAF_fprintf(outputfp, " v%d(",pDecInsn->vA);
        if (pDecInsn->opCode == OP_CONST_HIGH16) {
            s4 value = pDecInsn->vB << 16;

            printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
            DECAF_fprintf(outputfp, "), #int %E // #", value);
            printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
            /*DECAF_fprintf(outputfp,"(eknath7) v%d, #int %d // #%x",
                pDecInsn->vA, value, (u2)pDecInsn->vB);*/
        } else {
            s8 value = ((s8) pDecInsn->vB) << 48;
            printDalvikRegister(outputfp, env,pDecInsn->vA,operandTypeTable[pDecInsn->opCode][0]);
                        DECAF_fprintf(outputfp, "), #long %llE // #", value);
                        printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
            /*DECAF_fprintf(outputfp,"(eknath8) v%d, #long %lld // #%x",
                pDecInsn->vA, value, (u2)pDecInsn->vB);*/
        }
        break;
    case kFmt21c:        // op vAA, thing@BBBB
        DECAF_fprintf(outputfp," v%d(", pDecInsn->vA);
        if (pDecInsn->opCode == OP_CONST_STRING) {
            printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
            DECAF_fprintf(outputfp,"), \"%s\" // string@%04x",
                            //TODO:dexStringById(pDexFile, pDecInsn->vB), pDecInsn->vB);
                                    /*
                                     * dexStringById(pDexFile, pDecInsn->vB)
                                     * {    const DexStringId* pStringId = dexGetStringId(pDexFile, idx);
                                     *              return dexGetStringData(pDexFile, pStringId);
                                     * }
                                     *
                                     * dexGetStringId() returns &pDexFile->pStringIds[idx];
                                     *
                                     * dexGetStringData(){
                                     *              const u1* ptr = pDexFile->baseAddr + pStringId->stringDataOff;
                                     *              // Skip the uleb128 length.
                                     *              while (*(ptr++) > 0x7f)  ;
                                     *              return (const char*) ptr;
                                     * }
                                     */
                            "!!!!!FIXME!!!", pDecInsn->vB);
        } else if (pDecInsn->opCode == OP_CHECK_CAST ||
                   pDecInsn->opCode == OP_NEW_INSTANCE ||
                   pDecInsn->opCode == OP_CONST_CLASS)
        {
                DECAF_read_mem(env, getDalvikFP(env) + (pDecInsn->vA * 4), &vr_ival1, sizeof(u4));
                printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
            DECAF_fprintf(outputfp,"), %s // class@%04x",
//TODO:                getClassDescriptor(pDexFile, pDecInsn->vB), pDecInsn->vB);
                "!!!FIXME!!!", pDecInsn->vB);
        } else /* OP_SGET* */ {
          /*TODO: FIX ME
            FieldMethodInfo fieldInfo;

            if (getFieldInfo(pDexFile, pDecInsn->vB, &fieldInfo)) {
                DECAF_fprintf(outputfp," v%d, %s.%s:%s // field@%04x", pDecInsn->vA,
                    fieldInfo.classDescriptor, fieldInfo.name,
                    fieldInfo.signature, pDecInsn->vB);
            } else */{
                printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
                char s[256] = "???";
                getStaticFieldName(env, NULL, pDecInsn->vB, s, 256); //this shouldn't change s if
                // it fails, so just leave it like this without a test
                DECAF_fprintf(outputfp,"), %s // field@%04x", s, pDecInsn->vB);
            }
        }
        break;
    case kFmt23x:        // op vAA, vBB, vCC
        DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vB);
        printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
        DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vC);
        printDalvikRegister(outputfp, env,pDecInsn->vC, operandTypeTable[pDecInsn->opCode][2]);
        DECAF_fprintf(outputfp,")");
        //DECAF_fprintf(outputfp," v%d, v%d, v%d", pDecInsn->vA, pDecInsn->vB, pDecInsn->vC);
        break;
    case kFmt22b:        // op vAA, vBB, #+CC
        DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vB);
        printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
        DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vC);
        printDalvikRegister(outputfp, env,pDecInsn->vC, operandTypeTable[pDecInsn->opCode][2]);
        DECAF_fprintf(outputfp,")");


        //DECAF_fprintf(outputfp," (eknathD)v%d, v%d, #int %d // #%02x",
            //pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (u1)pDecInsn->vC);
        break;
    case kFmt22t:        // op vA, vB, +CCCC
        {
            s4 targ = (s4) pDecInsn->vC;
            DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
            printDalvikRegister(outputfp, env,pDecInsn->vA,operandTypeTable[pDecInsn->opCode][0]);
                DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vB);
                printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
                DECAF_fprintf(outputfp,"), %04x // %c%04x",
                //insnIdx + targ,
                (address - methodAddress) + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        }
        break;
    case kFmt22s:        // op vA, vB, #+CCCC
        DECAF_fprintf(outputfp,"v%d",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vB);
                printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
                DECAF_fprintf(outputfp,"), #int ");
                printDalvikRegister(outputfp, env,pDecInsn->vC, operandTypeTable[pDecInsn->opCode][2]);

        //DECAF_fprintf(outputfp,"v%d, v%d, #int %d // #%04x",
        //    pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (u2)pDecInsn->vC);
        break;
    case kFmt22c:        // op vA, vB, thing@CCCC
        DECAF_fprintf(outputfp,"v%d",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp,"), v%d(",pDecInsn->vB);
                printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);

        if (pDecInsn->opCode == OP_INSTANCE_OF ||
            pDecInsn->opCode == OP_NEW_ARRAY)
        {
            DECAF_fprintf(outputfp,", %s // class@%04x",
                //TODO: getClassDescriptor(pDexFile, pDecInsn->vC), pDecInsn->vC);
                "!!!FIXME!!!", pDecInsn->vC);
        } else {
            /* iget* and iput*, including dexopt-generated -volatile */
          /*TODO:
            FieldMethodInfo fieldInfo;
            if (getFieldInfo(pDexFile, pDecInsn->vC, &fieldInfo)) {
                DECAF_fprintf(outputfp," v%d, v%d, %s.%s:%s // field@%04x", pDecInsn->vA,
                    pDecInsn->vB, fieldInfo.classDescriptor, fieldInfo.name,
                    fieldInfo.signature, pDecInsn->vC);
            } else */{
                DECAF_fprintf(outputfp,", ??? // field@%04x",
                    pDecInsn->vC);
            }
        }
        break;
    case kFmt22cs:       // [opt] op vA, vB, field offset CCCC
        //EknathCheckThis NotIn netmite
        DECAF_fprintf(outputfp," v%d, v%d, [obj+%04x]",
            pDecInsn->vA, pDecInsn->vB, pDecInsn->vC);
        break;
    case kFmt30t:
        DECAF_fprintf(outputfp," #%08x", pDecInsn->vA);
        break;
    case kFmt31i:        // op vAA, #+BBBBBBBB
        {
            /* this is often, but not always, a float */
            union {
                float f;
                u4 i;
            } conv;
            conv.i = pDecInsn->vB;
            DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
            printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
            DECAF_fprintf(outputfp,"), #float %f // #",
                conv.f);
            DECAF_fprintf(outputfp, ", v%d(", pDecInsn->vB);
            printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
            DECAF_fprintf(outputfp, ")");
        }
        break;
    case kFmt31c:        // op vAA, thing@BBBBBBBB
        DECAF_fprintf(outputfp, " v%d(", pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        //TODO: dexStringById(pDexFile, pDecInsn->vB), pDecInsn->vB);
        DECAF_fprintf(outputfp, "), \"%s\" string@%08x", "!!!FIXME!!!", pDecInsn->vB);

        break;
    case kFmt31t:       // op vAA, offset +BBBBBBBB
        DECAF_fprintf(outputfp," v%d(",pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA,DALVIK_TYPE_NULL);

        DECAF_fprintf(outputfp,"), %08x // +%08x",
            //pDecInsn->vA, insnIdx + pDecInsn->vB, pDecInsn->vB);
            (address - methodAddress) + pDecInsn->vB, pDecInsn->vB);
        break;
    case kFmt32x:        // op vAAAA, vBBBB
        //DECAF_fprintf(outputfp,"(eknathM) v%d, v%d", pDecInsn->vA, pDecInsn->vB);
        DECAF_fprintf(outputfp, "v%d(", pDecInsn->vA);
        printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
        DECAF_fprintf(outputfp, ", v%d(", pDecInsn->vB);
        printDalvikRegister(outputfp, env,pDecInsn->vB, operandTypeTable[pDecInsn->opCode][1]);
        DECAF_fprintf(outputfp, ")");
        break;
    case kFmt35c:        // op vB, {vD, vE, vF, vG, vA}, thing@CCCC
        {
            /* NOTE: decoding of 35c doesn't quite match spec */
          DECAF_fprintf(outputfp, "{");
            for (i = 0; i < (int) pDecInsn->vA; i++)
                if (i == 0){
                    DECAF_fprintf(outputfp,"v%d(", pDecInsn->arg[i]);
                    printDalvikRegister(outputfp, env,pDecInsn->arg[i], DALVIK_TYPE_NULL);
                    DECAF_fprintf(outputfp,")");
                }
                else{
                    DECAF_fprintf(outputfp,", v%d(", pDecInsn->arg[i]);
                    printDalvikRegister(outputfp, env,pDecInsn->arg[i], DALVIK_TYPE_NULL);
                    DECAF_fprintf(outputfp,")");
                }

            if (pDecInsn->opCode == OP_FILLED_NEW_ARRAY) {
                DECAF_fprintf(outputfp,"}, %s // class@%04x",
                    //TODO:getClassDescriptor(pDexFile, pDecInsn->vB), pDecInsn->vB);
                    "!!!FIXME!!!", pDecInsn->vB);
            } else {
              int ret = 0;
                if ((ret = getMethodName(env, NULL, pDecInsn->vB, methodName, 128)) == 0)
                {
                  DECAF_fprintf(outputfp, "}, %s // method@%04x", methodName, pDecInsn->vB);
                }
                else
                {
                  DECAF_fprintf(outputfp,"}, ??? // method@%04x", pDecInsn->vB);
                }
            }
        }
        break;
    case kFmt35ms:       // [opt] invoke-virtual+super
    case kFmt35fs:       // [opt] invoke-interface
        {
            DECAF_fprintf(outputfp, " {");
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                {
                    DECAF_fprintf(outputfp,"v%d(", pDecInsn->arg[i]);
                    printDalvikRegister(outputfp, env, pDecInsn->arg[i], DALVIK_TYPE_NULL);
                    DECAF_fprintf(outputfp,")");
                    if (eLogLevel == LOG_LEVEL_VERBOSE)
                    {
                      u4 vrVal_4 = 0;
                      DECAF_read_mem(env, VREG_TO_GVA(env, pDecInsn->arg[i]), &vrVal_4, sizeof(u4));
                      printJavaStringAt(outputfp, env, vrVal_4);
                    }
                }
                else
                {
                    DECAF_fprintf(outputfp,", v%d(", pDecInsn->arg[i]);
                    printDalvikRegister(outputfp, env, pDecInsn->arg[i], DALVIK_TYPE_NULL);
                    DECAF_fprintf(outputfp,")");
                    if (eLogLevel == LOG_LEVEL_VERBOSE)
                    {
                      u4 vrVal_4 = 0;
                      DECAF_read_mem(env, VREG_TO_GVA(env, pDecInsn->arg[i]), &vrVal_4, sizeof(u4));
                      printJavaStringAt(outputfp, env, vrVal_4);
                    }
                }
            }
            //DECAF_fprintf(outputfp,"}, [%04x] // vtable #%04x", pDecInsn->vB, pDecInsn->vB);
            int ret = 0;
            if (( ret = getMethodNameByVtable(env, NULL, pDecInsn->vC, pDecInsn->vB, methodName, 128)) == 0)
            {
              DECAF_fprintf(outputfp, "}, %s // vtable@%04x", methodName, pDecInsn->vB);
            }
            else
            {
              DECAF_fprintf(outputfp, "}, ??? // vtable@%04x", methodName, pDecInsn->vB);
            }
        }
        break;
    case kFmt3rc:        // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
        {
            /*
             * This doesn't match the "dx" output when some of the args are
             * 64-bit values -- dx only shows the first register.
             */
            DECAF_fprintf(outputfp, " {");
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                {
                    DECAF_fprintf(outputfp,"v%d(", pDecInsn->vC + i);
                    printDalvikRegister(outputfp, env, pDecInsn->vC + i, DALVIK_TYPE_NULL);
                    DECAF_fprintf(outputfp,")");
                    if (eLogLevel == LOG_LEVEL_VERBOSE)
                    {
                      u4 vrVal_4 = 0;
                      DECAF_read_mem(env, VREG_TO_GVA(env, pDecInsn->arg[i]), &vrVal_4, sizeof(u4));
                      printJavaStringAt(outputfp, env, vrVal_4);
                    }
                }
                else
                {
                    DECAF_fprintf(outputfp,", v%d(", pDecInsn->vC + i);
                    printDalvikRegister(outputfp, env, pDecInsn->vC + i, DALVIK_TYPE_NULL);
                    DECAF_fprintf(outputfp,")");
                    if (eLogLevel == LOG_LEVEL_VERBOSE)
                    {
                      u4 vrVal_4 = 0;
                      DECAF_read_mem(env, VREG_TO_GVA(env, pDecInsn->arg[i]), &vrVal_4, sizeof(u4));
                      printJavaStringAt(outputfp, env, vrVal_4);
                    }
                }
            }
            if (pDecInsn->opCode == OP_FILLED_NEW_ARRAY_RANGE) {
                DECAF_fprintf(outputfp,"}, %s // class@%04x",
                    //TODO:getClassDescriptor(pDexFile, pDecInsn->vB), pDecInsn->vB);
                    "!!!FIXME!!!", pDecInsn->vB);
            } else {
              int ret = 0;
              if ((ret = getMethodName(env, NULL, pDecInsn->vB, methodName, 128)) == 0)
              {
                DECAF_fprintf(outputfp, "}, %s // method@%04x\n", methodName, pDecInsn->vB);
              }
              else
              {
                DECAF_fprintf(outputfp,"}, ??? // method@%04x", pDecInsn->vB);
              }

              /*TODO:
                FieldMethodInfo methInfo;
                if (getMethodInfo(pDexFile, pDecInsn->vB, &methInfo)) {
                    DECAF_fprintf(outputfp,"}, %s.%s:%s // method@%04x",
                        methInfo.classDescriptor, methInfo.name,
                        methInfo.signature, pDecInsn->vB);
                } else */
            }
        }
        break;
    case kFmt3rms:       // [opt] invoke-virtual+super/range
    case kFmt3rfs:       // [opt] invoke-interface/range
        {
            /*
             * This doesn't match the "dx" output when some of the args are
             * 64-bit values -- dx only shows the first register.
             */
            DECAF_fprintf(outputfp, " {");
            for (i = 0; i < (int) pDecInsn->vA; i++)
            {
              if (i == 0)
              {
                DECAF_fprintf(outputfp,"v%d(", pDecInsn->vC + i);
                printDalvikRegister(outputfp, env, pDecInsn->vC + i, DALVIK_TYPE_NULL);
                DECAF_fprintf(outputfp,")");
                if (eLogLevel == LOG_LEVEL_VERBOSE)
                {
                  u4 vrVal_4 = 0;
                  DECAF_read_mem(env, VREG_TO_GVA(env, pDecInsn->arg[i]), &vrVal_4, sizeof(u4));
                  printJavaStringAt(outputfp, env, vrVal_4);
                }
              }
              else
              {
                DECAF_fprintf(outputfp,", v%d(", pDecInsn->vC + i);
                printDalvikRegister(outputfp, env, pDecInsn->vC + i, DALVIK_TYPE_NULL);
                DECAF_fprintf(outputfp,")");
                if (eLogLevel == LOG_LEVEL_VERBOSE)
                {
                  u4 vrVal_4 = 0;
                  DECAF_read_mem(env, VREG_TO_GVA(env, pDecInsn->arg[i]), &vrVal_4, sizeof(u4));
                  printJavaStringAt(outputfp, env, vrVal_4);
                }
              }
            }
            int ret = 0;
            if (( ret = getMethodNameByVtable(env, NULL, pDecInsn->vC, pDecInsn->vB, methodName, 128)) == 0)
            {
              DECAF_fprintf(outputfp, "}, %s // vtable@%04x", methodName, pDecInsn->vB);
            }
            else
            {
              DECAF_fprintf(outputfp, "}, ??? %d // vtable@%04x", pDecInsn->vC, pDecInsn->vB);
            }
        }
        break;
    case kFmt3rinline:   // [opt] execute-inline/range
        {
          DECAF_fprintf(outputfp, "{");
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    DECAF_fprintf(outputfp,"v%d", pDecInsn->vC + i);
                else
                    DECAF_fprintf(outputfp,", v%d", pDecInsn->vC + i);
            }
            DECAF_fprintf(outputfp,"}, [%04x] // inline #%04x", pDecInsn->vB, pDecInsn->vB);
        }
        break;
    case kFmt3inline:    // [opt] inline invoke
        {
#if 0
            const InlineOperation* inlineOpsTable = dvmGetInlineOpsTable();
            u4 tableLen = dvmGetInlineOpsTableLength();
#endif

            DECAF_fprintf(outputfp, "(eknathS) {");
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    DECAF_fprintf(outputfp,"v%d", pDecInsn->arg[i]);
                else
                    DECAF_fprintf(outputfp,", v%d", pDecInsn->arg[i]);
            }
#if 0
            if (pDecInsn->vB < tableLen) {
                DECAF_fprintf(outputfp,"}, %s.%s:%s // inline #%04x",
                    inlineOpsTable[pDecInsn->vB].classDescriptor,
                    inlineOpsTable[pDecInsn->vB].methodName,
                    inlineOpsTable[pDecInsn->vB].methodSignature,
                    pDecInsn->vB);
            } else {
#endif
                DECAF_fprintf(outputfp,"}, [%04x] // inline #%04x", pDecInsn->vB, pDecInsn->vB);
#if 0
            }
#endif
        }
        break;
    case kFmt51l:        // op vAA, #+BBBBBBBBBBBBBBBB
        {

            /* this is often, but not always, a double */
            union {
                double d;
                u8 j;
            } conv;
            conv.j = pDecInsn->vB_wide;
            DECAF_fprintf(outputfp, "v%d(", pDecInsn->vA);
            printDalvikRegister(outputfp, env,pDecInsn->vA, operandTypeTable[pDecInsn->opCode][0]);
            DECAF_fprintf(outputfp,"), #double %f // #%016llx",
                conv.d, pDecInsn->vB_wide);
        }
        break;
    case kFmtUnknown:
        break;
    default:
        DECAF_fprintf(outputfp," ???");
        break;
    }

    //putchar('\n');
    DECAF_fprintf(outputfp, "\n");
}

int getDalvikInstruction(CPUState* env, gva_t rpc, int* pWidth, u2* pInsns, int len)
{
  if ( (gInstrWidth == NULL) || (gInstrFormat == NULL) )
  {
    return (UNINITIALIZED_ERROR);
  }

  if ( (env == NULL) || (pWidth == NULL) || (pInsns == NULL) )
  {
    return (NULL_POINTER_ERROR);
  }

  u2 instr = 0;
  u4 temp = 0;
  int insnWidth = 0;
  OpCode opCode;

  if (DECAF_read_mem(env, rpc, &instr, 2) != 0)
  {
    //DECAF_fprintf(apifp,"Failed to obtain instruction bytes 1,2\n");
    return (-1);
  }
  if (DECAF_read_mem(env, rpc + 2, &temp, 2) != 0)
  {
    //DECAF_fprintf(apifp,"Failed to obtain instruction bytes 2,3 \n");
    return (-2);
  }

  if (instr == kPackedSwitchSignature)
  {
    insnWidth = 4 + temp * 2;
  } else if (instr == kSparseSwitchSignature) {
    insnWidth = 2 + temp * 4;
  } else if (instr == kArrayDataSignature) {
    //int width = get2LE((const u1*)(insns+1));
    int width = temp;
    //int size = get2LE((const u1*)(insns+2)) |
    //             (get2LE((const u1*)(insns+3))<<16);
    int temp2;
    int temp3;
    if ( (DECAF_read_mem(env, rpc + 4, &temp2, 2) != 0) || (DECAF_read_mem(env, rpc + 6, &temp3, 2) != 0))
    {
      //DECAF_fprintf(apifp,"Failed to obtain instruction bytes 4-7 \n");
      return(-3);
    }

    int size = temp2 | (temp3 << 16);
      // The plus 1 is to round up for odd size and width
      insnWidth = 4 + ((size * width) + 1) / 2;
  } else {
      opCode = (OpCode)(instr & 0xff);
      insnWidth = dexGetInstrWidthAbs(gInstrWidth, opCode);
      if (insnWidth == 0) {
          //DECAF_fprintf(apifp,
              //"GLITCH: zero-width instruction at idx=0x%04x\n", rpc);
        return (-4);
      }
  }

  //at this point we have the instruction width
  if (insnWidth >= len)
  {
    //DECAF_fprintf(apifp,"WOW That is one big instruction\n");
    return (-5);
  }

  //populate the insns array
  if ( DECAF_read_mem(env, rpc, pInsns, insnWidth * 2) != 0)
  {
    //DECAF_fprintf(apifp,"Could not read the whole instruction\n");
    return (-6);
  }

  *pWidth = insnWidth;
  return (0);
}

inline void decodeDalvikInstruction(const u2* pInsns, DecodedInstruction* pDecInsn)
{
  if ( (gInstrWidth == NULL) || (gInstrFormat == NULL) )
  {
    return;
  }

  dexDecodeInstruction(gInstrFormat, pInsns, pDecInsn);
}

void DalvikPrinter_init(void)
{
  gInstrWidth = dexCreateInstrWidthTable();
  gInstrFormat = dexCreateInstrFormatTable();
}
