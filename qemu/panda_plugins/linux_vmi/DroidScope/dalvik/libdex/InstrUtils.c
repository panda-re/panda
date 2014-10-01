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
#include "InstrUtils.h"

#include <stdlib.h>


/*
 * Generate a table that holds the width of all instructions.
 *
 * Standard instructions have positive values, optimizer instructions
 * have negative values, unimplemented instructions have a width of zero.
 *
 * I'm doing it with a giant switch statement because it's easier to
 * maintain and update than a static table with 256 unadorned integers,
 * and if we're missing a case gcc emits a "warning: enumeration value not
 * handled" message.
 *
 * (To save space in the binary we could generate a static table with a
 * command-line utility.)
 *
 * TODO: it doesn't look like we're using the negative values anymore.
 * Consider switching to only positive values.
 */
InstructionWidth* dexCreateInstrWidthTable(void)
{
#ifdef __ARM_ARCH_7A__
    /* hack to work around mysterious problem on emulator */
    LOGD("creating instr width table\n");
#endif
    InstructionWidth* instrWidth;
    int i;

    instrWidth = malloc(sizeof(InstructionWidth) * kNumDalvikInstructions);
    if (instrWidth == NULL)
        return NULL;

    for (i = 0; i < kNumDalvikInstructions; i++) {
        OpCode opc = (OpCode) i;
        int width = 0;

        switch (opc) {
        case OP_NOP:    /* note data for e.g. switch-* encoded "inside" a NOP */
        case OP_MOVE:
        case OP_MOVE_WIDE:
        case OP_MOVE_OBJECT:
        case OP_MOVE_RESULT:
        case OP_MOVE_RESULT_WIDE:
        case OP_MOVE_RESULT_OBJECT:
        case OP_MOVE_EXCEPTION:
        case OP_RETURN_VOID:
        case OP_RETURN:
        case OP_RETURN_WIDE:
        case OP_RETURN_OBJECT:
        case OP_CONST_4:
        case OP_MONITOR_ENTER:
        case OP_MONITOR_EXIT:
        case OP_ARRAY_LENGTH:
        case OP_THROW:
        case OP_GOTO:
        case OP_NEG_INT:
        case OP_NOT_INT:
        case OP_NEG_LONG:
        case OP_NOT_LONG:
        case OP_NEG_FLOAT:
        case OP_NEG_DOUBLE:
        case OP_INT_TO_LONG:
        case OP_INT_TO_FLOAT:
        case OP_INT_TO_DOUBLE:
        case OP_LONG_TO_INT:
        case OP_LONG_TO_FLOAT:
        case OP_LONG_TO_DOUBLE:
        case OP_FLOAT_TO_INT:
        case OP_FLOAT_TO_LONG:
        case OP_FLOAT_TO_DOUBLE:
        case OP_DOUBLE_TO_INT:
        case OP_DOUBLE_TO_LONG:
        case OP_DOUBLE_TO_FLOAT:
        case OP_INT_TO_BYTE:
        case OP_INT_TO_CHAR:
        case OP_INT_TO_SHORT:
        case OP_ADD_INT_2ADDR:
        case OP_SUB_INT_2ADDR:
        case OP_MUL_INT_2ADDR:
        case OP_DIV_INT_2ADDR:
        case OP_REM_INT_2ADDR:
        case OP_AND_INT_2ADDR:
        case OP_OR_INT_2ADDR:
        case OP_XOR_INT_2ADDR:
        case OP_SHL_INT_2ADDR:
        case OP_SHR_INT_2ADDR:
        case OP_USHR_INT_2ADDR:
        case OP_ADD_LONG_2ADDR:
        case OP_SUB_LONG_2ADDR:
        case OP_MUL_LONG_2ADDR:
        case OP_DIV_LONG_2ADDR:
        case OP_REM_LONG_2ADDR:
        case OP_AND_LONG_2ADDR:
        case OP_OR_LONG_2ADDR:
        case OP_XOR_LONG_2ADDR:
        case OP_SHL_LONG_2ADDR:
        case OP_SHR_LONG_2ADDR:
        case OP_USHR_LONG_2ADDR:
        case OP_ADD_FLOAT_2ADDR:
        case OP_SUB_FLOAT_2ADDR:
        case OP_MUL_FLOAT_2ADDR:
        case OP_DIV_FLOAT_2ADDR:
        case OP_REM_FLOAT_2ADDR:
        case OP_ADD_DOUBLE_2ADDR:
        case OP_SUB_DOUBLE_2ADDR:
        case OP_MUL_DOUBLE_2ADDR:
        case OP_DIV_DOUBLE_2ADDR:
        case OP_REM_DOUBLE_2ADDR:
            width = 1;
            break;

        case OP_MOVE_FROM16:
        case OP_MOVE_WIDE_FROM16:
        case OP_MOVE_OBJECT_FROM16:
        case OP_CONST_16:
        case OP_CONST_HIGH16:
        case OP_CONST_WIDE_16:
        case OP_CONST_WIDE_HIGH16:
        case OP_CONST_STRING:
        case OP_CONST_CLASS:
        case OP_CHECK_CAST:
        case OP_INSTANCE_OF:
        case OP_NEW_INSTANCE:
        case OP_NEW_ARRAY:
        case OP_CMPL_FLOAT:
        case OP_CMPG_FLOAT:
        case OP_CMPL_DOUBLE:
        case OP_CMPG_DOUBLE:
        case OP_CMP_LONG:
        case OP_GOTO_16:
        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE:
        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ:
        case OP_AGET:
        case OP_AGET_WIDE:
        case OP_AGET_OBJECT:
        case OP_AGET_BOOLEAN:
        case OP_AGET_BYTE:
        case OP_AGET_CHAR:
        case OP_AGET_SHORT:
        case OP_APUT:
        case OP_APUT_WIDE:
        case OP_APUT_OBJECT:
        case OP_APUT_BOOLEAN:
        case OP_APUT_BYTE:
        case OP_APUT_CHAR:
        case OP_APUT_SHORT:
        case OP_IGET:
        case OP_IGET_WIDE:
        case OP_IGET_OBJECT:
        case OP_IGET_BOOLEAN:
        case OP_IGET_BYTE:
        case OP_IGET_CHAR:
        case OP_IGET_SHORT:
        case OP_IPUT:
        case OP_IPUT_WIDE:
        case OP_IPUT_OBJECT:
        case OP_IPUT_BOOLEAN:
        case OP_IPUT_BYTE:
        case OP_IPUT_CHAR:
        case OP_IPUT_SHORT:
        case OP_SGET:
        case OP_SGET_WIDE:
        case OP_SGET_OBJECT:
        case OP_SGET_BOOLEAN:
        case OP_SGET_BYTE:
        case OP_SGET_CHAR:
        case OP_SGET_SHORT:
        case OP_SPUT:
        case OP_SPUT_WIDE:
        case OP_SPUT_OBJECT:
        case OP_SPUT_BOOLEAN:
        case OP_SPUT_BYTE:
        case OP_SPUT_CHAR:
        case OP_SPUT_SHORT:
        case OP_ADD_INT:
        case OP_SUB_INT:
        case OP_MUL_INT:
        case OP_DIV_INT:
        case OP_REM_INT:
        case OP_AND_INT:
        case OP_OR_INT:
        case OP_XOR_INT:
        case OP_SHL_INT:
        case OP_SHR_INT:
        case OP_USHR_INT:
        case OP_ADD_LONG:
        case OP_SUB_LONG:
        case OP_MUL_LONG:
        case OP_DIV_LONG:
        case OP_REM_LONG:
        case OP_AND_LONG:
        case OP_OR_LONG:
        case OP_XOR_LONG:
        case OP_SHL_LONG:
        case OP_SHR_LONG:
        case OP_USHR_LONG:
        case OP_ADD_FLOAT:
        case OP_SUB_FLOAT:
        case OP_MUL_FLOAT:
        case OP_DIV_FLOAT:
        case OP_REM_FLOAT:
        case OP_ADD_DOUBLE:
        case OP_SUB_DOUBLE:
        case OP_MUL_DOUBLE:
        case OP_DIV_DOUBLE:
        case OP_REM_DOUBLE:
        case OP_ADD_INT_LIT16:
        case OP_RSUB_INT:
        case OP_MUL_INT_LIT16:
        case OP_DIV_INT_LIT16:
        case OP_REM_INT_LIT16:
        case OP_AND_INT_LIT16:
        case OP_OR_INT_LIT16:
        case OP_XOR_INT_LIT16:
        case OP_ADD_INT_LIT8:
        case OP_RSUB_INT_LIT8:
        case OP_MUL_INT_LIT8:
        case OP_DIV_INT_LIT8:
        case OP_REM_INT_LIT8:
        case OP_AND_INT_LIT8:
        case OP_OR_INT_LIT8:
        case OP_XOR_INT_LIT8:
        case OP_SHL_INT_LIT8:
        case OP_SHR_INT_LIT8:
        case OP_USHR_INT_LIT8:
            width = 2;
            break;

        case OP_MOVE_16:
        case OP_MOVE_WIDE_16:
        case OP_MOVE_OBJECT_16:
        case OP_CONST:
        case OP_CONST_WIDE_32:
        case OP_CONST_STRING_JUMBO:
        case OP_GOTO_32:
        case OP_FILLED_NEW_ARRAY:
        case OP_FILLED_NEW_ARRAY_RANGE:
        case OP_FILL_ARRAY_DATA:
        case OP_PACKED_SWITCH:
        case OP_SPARSE_SWITCH:
        case OP_INVOKE_VIRTUAL:
        case OP_INVOKE_SUPER:
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_STATIC:
        case OP_INVOKE_INTERFACE:
        case OP_INVOKE_VIRTUAL_RANGE:
        case OP_INVOKE_SUPER_RANGE:
        case OP_INVOKE_DIRECT_RANGE:
        case OP_INVOKE_STATIC_RANGE:
        case OP_INVOKE_INTERFACE_RANGE:
            width = 3;
            break;

        case OP_CONST_WIDE:
            width = 5;
            break;

        /*
         * Optimized instructions.  We return negative size values for these
         * to distinguish them.
         */
        case OP_IGET_QUICK:
        case OP_IGET_WIDE_QUICK:
        case OP_IGET_OBJECT_QUICK:
        case OP_IPUT_QUICK:
        case OP_IPUT_WIDE_QUICK:
        case OP_IPUT_OBJECT_QUICK:
        case OP_IGET_VOLATILE:
        case OP_IPUT_VOLATILE:
        case OP_SGET_VOLATILE:
        case OP_SPUT_VOLATILE:
        case OP_IGET_OBJECT_VOLATILE:
        case OP_IPUT_OBJECT_VOLATILE:
        case OP_SGET_OBJECT_VOLATILE:
        case OP_SPUT_OBJECT_VOLATILE:
        case OP_IGET_WIDE_VOLATILE:
        case OP_IPUT_WIDE_VOLATILE:
        case OP_SGET_WIDE_VOLATILE:
        case OP_SPUT_WIDE_VOLATILE:
        case OP_THROW_VERIFICATION_ERROR:
            width = -2;
            break;
        case OP_INVOKE_VIRTUAL_QUICK:
        case OP_INVOKE_VIRTUAL_QUICK_RANGE:
        case OP_INVOKE_SUPER_QUICK:
        case OP_INVOKE_SUPER_QUICK_RANGE:
        case OP_EXECUTE_INLINE:
        case OP_EXECUTE_INLINE_RANGE:
        case OP_INVOKE_DIRECT_EMPTY:
            width = -3;
            break;

        /* these should never appear when scanning bytecode */
        case OP_UNUSED_3E:
        case OP_UNUSED_3F:
        case OP_UNUSED_40:
        case OP_UNUSED_41:
        case OP_UNUSED_42:
        case OP_UNUSED_43:
        case OP_UNUSED_73:
        case OP_UNUSED_79:
        case OP_UNUSED_7A:
        case OP_BREAKPOINT:
        case OP_UNUSED_F1:
        case OP_UNUSED_FF:
            assert(width == 0);
            break;

        /*
         * DO NOT add a "default" clause here.  Without it the compiler will
         * complain if an instruction is missing (which is desirable).
         */
        }

        instrWidth[opc] = width;
    }

    return instrWidth;
}

/*
 * Generate a table that holds instruction flags.
 */
InstructionFlags* dexCreateInstrFlagsTable(void)
{
    InstructionFlags* instrFlags;
    int i;

    instrFlags = malloc(sizeof(InstructionFlags) * kNumDalvikInstructions);
    if (instrFlags == NULL)
        return NULL;

    for (i = 0; i < kNumDalvikInstructions; i++) {
        OpCode opc = (OpCode) i;
        InstructionFlags flags = 0;

        switch (opc) {
        /* these don't affect the PC and can't cause an exception */
        case OP_NOP:
        case OP_MOVE:
        case OP_MOVE_FROM16:
        case OP_MOVE_16:
        case OP_MOVE_WIDE:
        case OP_MOVE_WIDE_FROM16:
        case OP_MOVE_WIDE_16:
        case OP_MOVE_OBJECT:
        case OP_MOVE_OBJECT_FROM16:
        case OP_MOVE_OBJECT_16:
        case OP_MOVE_RESULT:
        case OP_MOVE_RESULT_WIDE:
        case OP_MOVE_RESULT_OBJECT:
        case OP_MOVE_EXCEPTION:
        case OP_CONST_4:
        case OP_CONST_16:
        case OP_CONST:
        case OP_CONST_HIGH16:
        case OP_CONST_WIDE_16:
        case OP_CONST_WIDE_32:
        case OP_CONST_WIDE:
        case OP_CONST_WIDE_HIGH16:
        case OP_FILL_ARRAY_DATA:
        case OP_CMPL_FLOAT:
        case OP_CMPG_FLOAT:
        case OP_CMPL_DOUBLE:
        case OP_CMPG_DOUBLE:
        case OP_CMP_LONG:
        case OP_NEG_INT:
        case OP_NOT_INT:
        case OP_NEG_LONG:
        case OP_NOT_LONG:
        case OP_NEG_FLOAT:
        case OP_NEG_DOUBLE:
        case OP_INT_TO_LONG:
        case OP_INT_TO_FLOAT:
        case OP_INT_TO_DOUBLE:
        case OP_LONG_TO_INT:
        case OP_LONG_TO_FLOAT:
        case OP_LONG_TO_DOUBLE:
        case OP_FLOAT_TO_INT:
        case OP_FLOAT_TO_LONG:
        case OP_FLOAT_TO_DOUBLE:
        case OP_DOUBLE_TO_INT:
        case OP_DOUBLE_TO_LONG:
        case OP_DOUBLE_TO_FLOAT:
        case OP_INT_TO_BYTE:
        case OP_INT_TO_CHAR:
        case OP_INT_TO_SHORT:
        case OP_ADD_INT:
        case OP_SUB_INT:
        case OP_MUL_INT:
        case OP_AND_INT:
        case OP_OR_INT:
        case OP_XOR_INT:
        case OP_SHL_INT:
        case OP_SHR_INT:
        case OP_USHR_INT:
        case OP_ADD_LONG:
        case OP_SUB_LONG:
        case OP_MUL_LONG:
        case OP_AND_LONG:
        case OP_OR_LONG:
        case OP_XOR_LONG:
        case OP_SHL_LONG:
        case OP_SHR_LONG:
        case OP_USHR_LONG:
        case OP_ADD_FLOAT:
        case OP_SUB_FLOAT:
        case OP_MUL_FLOAT:
        case OP_DIV_FLOAT:
        case OP_REM_FLOAT:
        case OP_ADD_DOUBLE:
        case OP_SUB_DOUBLE:
        case OP_MUL_DOUBLE:
        case OP_DIV_DOUBLE:         // div by zero just returns NaN
        case OP_REM_DOUBLE:
        case OP_ADD_INT_2ADDR:
        case OP_SUB_INT_2ADDR:
        case OP_MUL_INT_2ADDR:
        case OP_AND_INT_2ADDR:
        case OP_OR_INT_2ADDR:
        case OP_XOR_INT_2ADDR:
        case OP_SHL_INT_2ADDR:
        case OP_SHR_INT_2ADDR:
        case OP_USHR_INT_2ADDR:
        case OP_ADD_LONG_2ADDR:
        case OP_SUB_LONG_2ADDR:
        case OP_MUL_LONG_2ADDR:
        case OP_AND_LONG_2ADDR:
        case OP_OR_LONG_2ADDR:
        case OP_XOR_LONG_2ADDR:
        case OP_SHL_LONG_2ADDR:
        case OP_SHR_LONG_2ADDR:
        case OP_USHR_LONG_2ADDR:
        case OP_ADD_FLOAT_2ADDR:
        case OP_SUB_FLOAT_2ADDR:
        case OP_MUL_FLOAT_2ADDR:
        case OP_DIV_FLOAT_2ADDR:
        case OP_REM_FLOAT_2ADDR:
        case OP_ADD_DOUBLE_2ADDR:
        case OP_SUB_DOUBLE_2ADDR:
        case OP_MUL_DOUBLE_2ADDR:
        case OP_DIV_DOUBLE_2ADDR:
        case OP_REM_DOUBLE_2ADDR:
        case OP_ADD_INT_LIT16:
        case OP_RSUB_INT:
        case OP_MUL_INT_LIT16:
        case OP_AND_INT_LIT16:
        case OP_OR_INT_LIT16:
        case OP_XOR_INT_LIT16:
        case OP_ADD_INT_LIT8:
        case OP_RSUB_INT_LIT8:
        case OP_MUL_INT_LIT8:
        case OP_AND_INT_LIT8:
        case OP_OR_INT_LIT8:
        case OP_XOR_INT_LIT8:
        case OP_SHL_INT_LIT8:
        case OP_SHR_INT_LIT8:
        case OP_USHR_INT_LIT8:
            flags = kInstrCanContinue;
            break;

        /* these don't affect the PC, but can cause exceptions */
        case OP_CONST_STRING:
        case OP_CONST_STRING_JUMBO:
        case OP_CONST_CLASS:
        case OP_MONITOR_ENTER:
        case OP_MONITOR_EXIT:
        case OP_CHECK_CAST:
        case OP_INSTANCE_OF:
        case OP_ARRAY_LENGTH:
        case OP_NEW_INSTANCE:
        case OP_NEW_ARRAY:
        case OP_FILLED_NEW_ARRAY:
        case OP_FILLED_NEW_ARRAY_RANGE:
        case OP_AGET:
        case OP_AGET_BOOLEAN:
        case OP_AGET_BYTE:
        case OP_AGET_CHAR:
        case OP_AGET_SHORT:
        case OP_AGET_WIDE:
        case OP_AGET_OBJECT:
        case OP_APUT:
        case OP_APUT_BOOLEAN:
        case OP_APUT_BYTE:
        case OP_APUT_CHAR:
        case OP_APUT_SHORT:
        case OP_APUT_WIDE:
        case OP_APUT_OBJECT:
        case OP_IGET:
        case OP_IGET_BOOLEAN:
        case OP_IGET_BYTE:
        case OP_IGET_CHAR:
        case OP_IGET_SHORT:
        case OP_IGET_WIDE:
        case OP_IGET_OBJECT:
        case OP_IPUT:
        case OP_IPUT_BOOLEAN:
        case OP_IPUT_BYTE:
        case OP_IPUT_CHAR:
        case OP_IPUT_SHORT:
        case OP_IPUT_WIDE:
        case OP_IPUT_OBJECT:
        case OP_SGET:
        case OP_SGET_BOOLEAN:
        case OP_SGET_BYTE:
        case OP_SGET_CHAR:
        case OP_SGET_SHORT:
        case OP_SGET_WIDE:
        case OP_SGET_OBJECT:
        case OP_SPUT:
        case OP_SPUT_BOOLEAN:
        case OP_SPUT_BYTE:
        case OP_SPUT_CHAR:
        case OP_SPUT_SHORT:
        case OP_SPUT_WIDE:
        case OP_SPUT_OBJECT:
        case OP_DIV_INT:
        case OP_REM_INT:
        case OP_DIV_LONG:
        case OP_REM_LONG:
        case OP_DIV_INT_2ADDR:
        case OP_REM_INT_2ADDR:
        case OP_DIV_LONG_2ADDR:
        case OP_REM_LONG_2ADDR:
        case OP_DIV_INT_LIT16:
        case OP_REM_INT_LIT16:
        case OP_DIV_INT_LIT8:
        case OP_REM_INT_LIT8:
            flags = kInstrCanContinue | kInstrCanThrow;
            break;

        case OP_INVOKE_VIRTUAL:
        case OP_INVOKE_VIRTUAL_RANGE:
        case OP_INVOKE_SUPER:
        case OP_INVOKE_SUPER_RANGE:
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_DIRECT_RANGE:
        case OP_INVOKE_STATIC:
        case OP_INVOKE_STATIC_RANGE:
        case OP_INVOKE_INTERFACE:
        case OP_INVOKE_INTERFACE_RANGE:
            flags = kInstrCanContinue | kInstrCanThrow | kInstrInvoke;
            break;

        case OP_RETURN_VOID:
        case OP_RETURN:
        case OP_RETURN_WIDE:
        case OP_RETURN_OBJECT:
            flags = kInstrCanReturn;
            break;

        case OP_THROW:
            flags = kInstrCanThrow;
            break;

        /* unconditional branches */
        case OP_GOTO:
        case OP_GOTO_16:
        case OP_GOTO_32:
            flags = kInstrCanBranch | kInstrUnconditional;
            break;

        /* conditional branches */
        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE:
        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ:
            flags = kInstrCanBranch | kInstrCanContinue;
            break;

        /* switch statements; if value not in switch, it continues */
        case OP_PACKED_SWITCH:
        case OP_SPARSE_SWITCH:
            flags = kInstrCanSwitch | kInstrCanContinue;
            break;

        /* verifier/optimizer-generated instructions */
        case OP_THROW_VERIFICATION_ERROR:
            flags = kInstrCanThrow;
            break;
        case OP_EXECUTE_INLINE:
        case OP_EXECUTE_INLINE_RANGE:
            flags = kInstrCanContinue | kInstrCanThrow;
            break;
        case OP_IGET_QUICK:
        case OP_IGET_WIDE_QUICK:
        case OP_IGET_OBJECT_QUICK:
        case OP_IPUT_QUICK:
        case OP_IPUT_WIDE_QUICK:
        case OP_IPUT_OBJECT_QUICK:
        case OP_IGET_VOLATILE:
        case OP_IPUT_VOLATILE:
        case OP_SGET_VOLATILE:
        case OP_SPUT_VOLATILE:
        case OP_IGET_OBJECT_VOLATILE:
        case OP_IPUT_OBJECT_VOLATILE:
        case OP_SGET_OBJECT_VOLATILE:
        case OP_SPUT_OBJECT_VOLATILE:
        case OP_IGET_WIDE_VOLATILE:
        case OP_IPUT_WIDE_VOLATILE:
        case OP_SGET_WIDE_VOLATILE:
        case OP_SPUT_WIDE_VOLATILE:
            flags = kInstrCanContinue | kInstrCanThrow;
            break;

        case OP_INVOKE_VIRTUAL_QUICK:
        case OP_INVOKE_VIRTUAL_QUICK_RANGE:
        case OP_INVOKE_SUPER_QUICK:
        case OP_INVOKE_SUPER_QUICK_RANGE:
        case OP_INVOKE_DIRECT_EMPTY:
            flags = kInstrCanContinue | kInstrCanThrow | kInstrInvoke;
            break;

        /* these should never appear when scanning code */
        case OP_UNUSED_3E:
        case OP_UNUSED_3F:
        case OP_UNUSED_40:
        case OP_UNUSED_41:
        case OP_UNUSED_42:
        case OP_UNUSED_43:
        case OP_UNUSED_73:
        case OP_UNUSED_79:
        case OP_UNUSED_7A:
        case OP_BREAKPOINT:
        case OP_UNUSED_F1:
        case OP_UNUSED_FF:
            break;

        /*
         * DO NOT add a "default" clause here.  Without it the compiler will
         * complain if an instruction is missing (which is desirable).
         */
        }

        instrFlags[opc] = flags;
    }

    return instrFlags;
}

/*
 * Allocate and populate a 256-element array with instruction formats.
 * Used in conjunction with dexDecodeInstruction.
 */
InstructionFormat* dexCreateInstrFormatTable(void)
{
    InstructionFormat* instFmt;
    int i;

    instFmt = malloc(sizeof(InstructionFormat) * kNumDalvikInstructions);
    if (instFmt == NULL)
        return NULL;

    for (i = 0; i < kNumDalvikInstructions; i++) {
        OpCode opc = (OpCode) i;
        InstructionFormat fmt = kFmtUnknown;

        switch (opc) {
        case OP_GOTO:
            fmt = kFmt10t;
            break;
        case OP_NOP:
        case OP_RETURN_VOID:
            fmt = kFmt10x;
            break;
        case OP_CONST_4:
            fmt = kFmt11n;
            break;
        case OP_CONST_HIGH16:
        case OP_CONST_WIDE_HIGH16:
            fmt = kFmt21h;
            break;
        case OP_MOVE_RESULT:
        case OP_MOVE_RESULT_WIDE:
        case OP_MOVE_RESULT_OBJECT:
        case OP_MOVE_EXCEPTION:
        case OP_RETURN:
        case OP_RETURN_WIDE:
        case OP_RETURN_OBJECT:
        case OP_MONITOR_ENTER:
        case OP_MONITOR_EXIT:
        case OP_THROW:
            fmt = kFmt11x;
            break;
        case OP_MOVE:
        case OP_MOVE_WIDE:
        case OP_MOVE_OBJECT:
        case OP_ARRAY_LENGTH:
        case OP_NEG_INT:
        case OP_NOT_INT:
        case OP_NEG_LONG:
        case OP_NOT_LONG:
        case OP_NEG_FLOAT:
        case OP_NEG_DOUBLE:
        case OP_INT_TO_LONG:
        case OP_INT_TO_FLOAT:
        case OP_INT_TO_DOUBLE:
        case OP_LONG_TO_INT:
        case OP_LONG_TO_FLOAT:
        case OP_LONG_TO_DOUBLE:
        case OP_FLOAT_TO_INT:
        case OP_FLOAT_TO_LONG:
        case OP_FLOAT_TO_DOUBLE:
        case OP_DOUBLE_TO_INT:
        case OP_DOUBLE_TO_LONG:
        case OP_DOUBLE_TO_FLOAT:
        case OP_INT_TO_BYTE:
        case OP_INT_TO_CHAR:
        case OP_INT_TO_SHORT:
        case OP_ADD_INT_2ADDR:
        case OP_SUB_INT_2ADDR:
        case OP_MUL_INT_2ADDR:
        case OP_DIV_INT_2ADDR:
        case OP_REM_INT_2ADDR:
        case OP_AND_INT_2ADDR:
        case OP_OR_INT_2ADDR:
        case OP_XOR_INT_2ADDR:
        case OP_SHL_INT_2ADDR:
        case OP_SHR_INT_2ADDR:
        case OP_USHR_INT_2ADDR:
        case OP_ADD_LONG_2ADDR:
        case OP_SUB_LONG_2ADDR:
        case OP_MUL_LONG_2ADDR:
        case OP_DIV_LONG_2ADDR:
        case OP_REM_LONG_2ADDR:
        case OP_AND_LONG_2ADDR:
        case OP_OR_LONG_2ADDR:
        case OP_XOR_LONG_2ADDR:
        case OP_SHL_LONG_2ADDR:
        case OP_SHR_LONG_2ADDR:
        case OP_USHR_LONG_2ADDR:
        case OP_ADD_FLOAT_2ADDR:
        case OP_SUB_FLOAT_2ADDR:
        case OP_MUL_FLOAT_2ADDR:
        case OP_DIV_FLOAT_2ADDR:
        case OP_REM_FLOAT_2ADDR:
        case OP_ADD_DOUBLE_2ADDR:
        case OP_SUB_DOUBLE_2ADDR:
        case OP_MUL_DOUBLE_2ADDR:
        case OP_DIV_DOUBLE_2ADDR:
        case OP_REM_DOUBLE_2ADDR:
            fmt = kFmt12x;
            break;
        case OP_GOTO_16:
            fmt = kFmt20t;
            break;
        case OP_GOTO_32:
            fmt = kFmt30t;
            break;
        case OP_CONST_STRING:
        case OP_CONST_CLASS:
        case OP_CHECK_CAST:
        case OP_NEW_INSTANCE:
        case OP_SGET:
        case OP_SGET_WIDE:
        case OP_SGET_OBJECT:
        case OP_SGET_BOOLEAN:
        case OP_SGET_BYTE:
        case OP_SGET_CHAR:
        case OP_SGET_SHORT:
        case OP_SPUT:
        case OP_SPUT_WIDE:
        case OP_SPUT_OBJECT:
        case OP_SPUT_BOOLEAN:
        case OP_SPUT_BYTE:
        case OP_SPUT_CHAR:
        case OP_SPUT_SHORT:
            fmt = kFmt21c;
            break;
        case OP_CONST_16:
        case OP_CONST_WIDE_16:
            fmt = kFmt21s;
            break;
        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ:
            fmt = kFmt21t;
            break;
        case OP_FILL_ARRAY_DATA:
        case OP_PACKED_SWITCH:
        case OP_SPARSE_SWITCH:
            fmt = kFmt31t;
            break;
        case OP_ADD_INT_LIT8:
        case OP_RSUB_INT_LIT8:
        case OP_MUL_INT_LIT8:
        case OP_DIV_INT_LIT8:
        case OP_REM_INT_LIT8:
        case OP_AND_INT_LIT8:
        case OP_OR_INT_LIT8:
        case OP_XOR_INT_LIT8:
        case OP_SHL_INT_LIT8:
        case OP_SHR_INT_LIT8:
        case OP_USHR_INT_LIT8:
            fmt = kFmt22b;
            break;
        case OP_INSTANCE_OF:
        case OP_NEW_ARRAY:
        case OP_IGET:
        case OP_IGET_WIDE:
        case OP_IGET_OBJECT:
        case OP_IGET_BOOLEAN:
        case OP_IGET_BYTE:
        case OP_IGET_CHAR:
        case OP_IGET_SHORT:
        case OP_IPUT:
        case OP_IPUT_WIDE:
        case OP_IPUT_OBJECT:
        case OP_IPUT_BOOLEAN:
        case OP_IPUT_BYTE:
        case OP_IPUT_CHAR:
        case OP_IPUT_SHORT:
            fmt = kFmt22c;
            break;
        case OP_ADD_INT_LIT16:
        case OP_RSUB_INT:
        case OP_MUL_INT_LIT16:
        case OP_DIV_INT_LIT16:
        case OP_REM_INT_LIT16:
        case OP_AND_INT_LIT16:
        case OP_OR_INT_LIT16:
        case OP_XOR_INT_LIT16:
            fmt = kFmt22s;
            break;
        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE:
            fmt = kFmt22t;
            break;
        case OP_MOVE_FROM16:
        case OP_MOVE_WIDE_FROM16:
        case OP_MOVE_OBJECT_FROM16:
            fmt = kFmt22x;
            break;
        case OP_CMPL_FLOAT:
        case OP_CMPG_FLOAT:
        case OP_CMPL_DOUBLE:
        case OP_CMPG_DOUBLE:
        case OP_CMP_LONG:
        case OP_AGET:
        case OP_AGET_WIDE:
        case OP_AGET_OBJECT:
        case OP_AGET_BOOLEAN:
        case OP_AGET_BYTE:
        case OP_AGET_CHAR:
        case OP_AGET_SHORT:
        case OP_APUT:
        case OP_APUT_WIDE:
        case OP_APUT_OBJECT:
        case OP_APUT_BOOLEAN:
        case OP_APUT_BYTE:
        case OP_APUT_CHAR:
        case OP_APUT_SHORT:
        case OP_ADD_INT:
        case OP_SUB_INT:
        case OP_MUL_INT:
        case OP_DIV_INT:
        case OP_REM_INT:
        case OP_AND_INT:
        case OP_OR_INT:
        case OP_XOR_INT:
        case OP_SHL_INT:
        case OP_SHR_INT:
        case OP_USHR_INT:
        case OP_ADD_LONG:
        case OP_SUB_LONG:
        case OP_MUL_LONG:
        case OP_DIV_LONG:
        case OP_REM_LONG:
        case OP_AND_LONG:
        case OP_OR_LONG:
        case OP_XOR_LONG:
        case OP_SHL_LONG:
        case OP_SHR_LONG:
        case OP_USHR_LONG:
        case OP_ADD_FLOAT:
        case OP_SUB_FLOAT:
        case OP_MUL_FLOAT:
        case OP_DIV_FLOAT:
        case OP_REM_FLOAT:
        case OP_ADD_DOUBLE:
        case OP_SUB_DOUBLE:
        case OP_MUL_DOUBLE:
        case OP_DIV_DOUBLE:
        case OP_REM_DOUBLE:
            fmt = kFmt23x;
            break;
        case OP_CONST:
        case OP_CONST_WIDE_32:
            fmt = kFmt31i;
            break;
        case OP_CONST_STRING_JUMBO:
            fmt = kFmt31c;
            break;
        case OP_MOVE_16:
        case OP_MOVE_WIDE_16:
        case OP_MOVE_OBJECT_16:
            fmt = kFmt32x;
            break;
        case OP_FILLED_NEW_ARRAY:
        case OP_INVOKE_VIRTUAL:
        case OP_INVOKE_SUPER:
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_STATIC:
        case OP_INVOKE_INTERFACE:
            fmt = kFmt35c;
            break;
        case OP_FILLED_NEW_ARRAY_RANGE:
        case OP_INVOKE_VIRTUAL_RANGE:
        case OP_INVOKE_SUPER_RANGE:
        case OP_INVOKE_DIRECT_RANGE:
        case OP_INVOKE_STATIC_RANGE:
        case OP_INVOKE_INTERFACE_RANGE:
            fmt = kFmt3rc;
            break;
        case OP_CONST_WIDE:
            fmt = kFmt51l;
            break;

        /*
         * Optimized instructions.
         */
        case OP_THROW_VERIFICATION_ERROR:
            fmt = kFmt20bc;
            break;
        case OP_IGET_WIDE_VOLATILE:
        case OP_IPUT_WIDE_VOLATILE:
        case OP_IGET_VOLATILE:
        case OP_IPUT_VOLATILE:
        case OP_IGET_OBJECT_VOLATILE:
        case OP_IPUT_OBJECT_VOLATILE:
            fmt = kFmt22c;
            break;
        case OP_SGET_OBJECT_VOLATILE:
        case OP_SPUT_OBJECT_VOLATILE:
        case OP_SGET_VOLATILE:
        case OP_SPUT_VOLATILE:
        case OP_SGET_WIDE_VOLATILE:
        case OP_SPUT_WIDE_VOLATILE:
            fmt = kFmt21c;
            break;
        case OP_IGET_QUICK:
        case OP_IGET_WIDE_QUICK:
        case OP_IGET_OBJECT_QUICK:
        case OP_IPUT_QUICK:
        case OP_IPUT_WIDE_QUICK:
        case OP_IPUT_OBJECT_QUICK:
            fmt = kFmt22cs;
            break;
        case OP_INVOKE_VIRTUAL_QUICK:
        case OP_INVOKE_SUPER_QUICK:
            fmt = kFmt35ms;
            break;
        case OP_INVOKE_VIRTUAL_QUICK_RANGE:
        case OP_INVOKE_SUPER_QUICK_RANGE:
            fmt = kFmt3rms;
            break;
        case OP_EXECUTE_INLINE:
            fmt = kFmt3inline;
            break;
        case OP_EXECUTE_INLINE_RANGE:
            fmt = kFmt3rinline;
            break;
        case OP_INVOKE_DIRECT_EMPTY:
            fmt = kFmt35c;
            break;

        /* these should never appear when scanning code */
        case OP_UNUSED_3E:
        case OP_UNUSED_3F:
        case OP_UNUSED_40:
        case OP_UNUSED_41:
        case OP_UNUSED_42:
        case OP_UNUSED_43:
        case OP_UNUSED_73:
        case OP_UNUSED_79:
        case OP_UNUSED_7A:
        case OP_BREAKPOINT:
        case OP_UNUSED_F1:
        case OP_UNUSED_FF:
            fmt = kFmtUnknown;
            break;

        /*
         * DO NOT add a "default" clause here.  Without it the compiler will
         * complain if an instruction is missing (which is desirable).
         */
        }

        instFmt[opc] = fmt;
    }

    return instFmt;
}

/*
 * Copied from InterpCore.h.  Used for instruction decoding.
 */
#define FETCH(_offset)      (insns[(_offset)])
#define INST_INST(_inst)    ((_inst) & 0xff)
#define INST_A(_inst)       (((u2)(_inst) >> 8) & 0x0f)
#define INST_B(_inst)       ((u2)(_inst) >> 12)
#define INST_AA(_inst)      ((_inst) >> 8)

/*
 * Decode the instruction pointed to by "insns".
 *
 * Fills out the pieces of "pDec" that are affected by the current
 * instruction.  Does not touch anything else.
 */
void dexDecodeInstruction(const InstructionFormat* fmts, const u2* insns,
    DecodedInstruction* pDec)
{
    u2 inst = *insns;

    pDec->opCode = (OpCode) INST_INST(inst);

    switch (dexGetInstrFormat(fmts, pDec->opCode)) {
    case kFmt10x:       // op
        /* nothing to do; copy the AA bits out for the verifier */
        pDec->vA = INST_AA(inst);
        break;
    case kFmt12x:       // op vA, vB
        pDec->vA = INST_A(inst);
        pDec->vB = INST_B(inst);
        break;
    case kFmt11n:       // op vA, #+B
        pDec->vA = INST_A(inst);
        pDec->vB = (s4) (INST_B(inst) << 28) >> 28; // sign extend 4-bit value
        break;
    case kFmt11x:       // op vAA
        pDec->vA = INST_AA(inst);
        break;
    case kFmt10t:       // op +AA
        pDec->vA = (s1) INST_AA(inst);              // sign-extend 8-bit value
        break;
    case kFmt20t:       // op +AAAA
        pDec->vA = (s2) FETCH(1);                   // sign-extend 16-bit value
        break;
    case kFmt20bc:      // op AA, thing@BBBB
    case kFmt21c:       // op vAA, thing@BBBB
    case kFmt22x:       // op vAA, vBBBB
        pDec->vA = INST_AA(inst);
        pDec->vB = FETCH(1);
        break;
    case kFmt21s:       // op vAA, #+BBBB
    case kFmt21t:       // op vAA, +BBBB
        pDec->vA = INST_AA(inst);
        pDec->vB = (s2) FETCH(1);                   // sign-extend 16-bit value
        break;
    case kFmt21h:       // op vAA, #+BBBB0000[00000000]
        pDec->vA = INST_AA(inst);
        /*
         * The value should be treated as right-zero-extended, but we don't
         * actually do that here. Among other things, we don't know if it's
         * the top bits of a 32- or 64-bit value.
         */
        pDec->vB = FETCH(1);
        break;
    case kFmt23x:       // op vAA, vBB, vCC
        pDec->vA = INST_AA(inst);
        pDec->vB = FETCH(1) & 0xff;
        pDec->vC = FETCH(1) >> 8;
        break;
    case kFmt22b:       // op vAA, vBB, #+CC
        pDec->vA = INST_AA(inst);
        pDec->vB = FETCH(1) & 0xff;
        pDec->vC = (s1) (FETCH(1) >> 8);            // sign-extend 8-bit value
        break;
    case kFmt22s:       // op vA, vB, #+CCCC
    case kFmt22t:       // op vA, vB, +CCCC
        pDec->vA = INST_A(inst);
        pDec->vB = INST_B(inst);
        pDec->vC = (s2) FETCH(1);                   // sign-extend 16-bit value
        break;
    case kFmt22c:       // op vA, vB, thing@CCCC
    case kFmt22cs:      // [opt] op vA, vB, field offset CCCC
        pDec->vA = INST_A(inst);
        pDec->vB = INST_B(inst);
        pDec->vC = FETCH(1);
        break;
    case kFmt30t:        // op +AAAAAAAA
        pDec->vA = FETCH(1) | ((u4) FETCH(2) << 16); // signed 32-bit value
        break;
    case kFmt31t:       // op vAA, +BBBBBBBB
    case kFmt31c:       // op vAA, thing@BBBBBBBB
        pDec->vA = INST_AA(inst);
        pDec->vB = FETCH(1) | ((u4) FETCH(2) << 16); // 32-bit value
        break;
    case kFmt32x:       // op vAAAA, vBBBB
        pDec->vA = FETCH(1);
        pDec->vB = FETCH(2);
        break;
    case kFmt31i:       // op vAA, #+BBBBBBBB
        pDec->vA = INST_AA(inst);
        pDec->vB = FETCH(1) | ((u4) FETCH(2) << 16);
        break;
    case kFmt35c:       // op vB, {vD..vG,vA}, thing@CCCC
    case kFmt35ms:      // [opt] invoke-virtual+super
        {
            /*
             * The lettering changes that came about when we went from 4 args
             * to 5 made the "range" versions of the calls different from
             * the non-range versions.  We have the choice between decoding
             * them the way the spec shows and having lots of conditionals
             * in the verifier, or mapping the values onto their original
             * registers and leaving the verifier intact.
             *
             * Current plan is to leave the verifier alone.  We can fix it
             * later if it's architecturally unbearable.
             *
             * Bottom line: method constant is always in vB.
             */
            u2 regList;
            int i, count;

            pDec->vA = INST_B(inst);
            pDec->vB = FETCH(1);
            regList = FETCH(2);

            if (pDec->vA > 5) {
                //LOGW("Invalid arg count in 35c/35ms (%d)\n", pDec->vA);
                goto bail;
            }
            count = pDec->vA;
            if (count == 5) {
                /* 5th arg comes from A field in instruction */
                pDec->arg[4] = INST_A(inst);
                count--;
            }
            for (i = 0; i < count; i++) {
                pDec->arg[i] = regList & 0x0f;
                regList >>= 4;
            }
            /* copy arg[0] to vC; we don't have vD/vE/vF, so ignore those */
            if (pDec->vA > 0)
                pDec->vC = pDec->arg[0];
        }
        break;
    case kFmt3inline:   // [opt] inline invoke
        {
            u2 regList;
            int i;

            pDec->vA = INST_B(inst);
            pDec->vB = FETCH(1);
            regList = FETCH(2);

            if (pDec->vA > 4) {
                //LOGW("Invalid arg count in 3inline (%d)\n", pDec->vA);
                goto bail;
            }
            for (i = 0; i < (int) pDec->vA; i++) {
                pDec->arg[i] = regList & 0x0f;
                regList >>= 4;
            }
            /* copy arg[0] to vC; we don't have vD/vE/vF, so ignore those */
            if (pDec->vA > 0)
                pDec->vC = pDec->arg[0];
        }
        break;
    case kFmt35fs:      // [opt] invoke-interface
        assert(false);  // TODO
        break;
    case kFmt3rc:       // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
    case kFmt3rms:      // [opt] invoke-virtual+super/range
    case kFmt3rinline:  // [opt] execute-inline/range
        pDec->vA = INST_AA(inst);
        pDec->vB = FETCH(1);
        pDec->vC = FETCH(2);
        break;
    case kFmt3rfs:      // [opt] invoke-interface/range
        assert(false);  // TODO
        break;
    case kFmt51l:       // op vAA, #+BBBBBBBBBBBBBBBB
        pDec->vA = INST_AA(inst);
        pDec->vB_wide = FETCH(1);
        pDec->vB_wide |= (u8)FETCH(2) << 16;
        pDec->vB_wide |= (u8)FETCH(3) << 32;
        pDec->vB_wide |= (u8)FETCH(4) << 48;
        break;
    default:
        //LOGW("Can't decode unexpected format %d (op=%d)\n",
            //dexGetInstrFormat(fmts, pDec->opCode), pDec->opCode);
        assert(false);
        break;
    }

bail:
    ;
}

/*
 * Return the width of the specified instruction, or 0 if not defined.  Also
 * works for special OP_NOP entries, including switch statement data tables
 * and array data.
 */
size_t dexGetInstrOrTableWidthAbs(const InstructionWidth* widths,
    const u2* insns)
{
    size_t width;

    if (*insns == kPackedSwitchSignature) {
        width = 4 + insns[1] * 2;
    } else if (*insns == kSparseSwitchSignature) {
        width = 2 + insns[1] * 4;
    } else if (*insns == kArrayDataSignature) {
        u2 elemWidth = insns[1];
        u4 len = insns[2] | (((u4)insns[3]) << 16);
        width = 4 + (elemWidth * len + 1) / 2;
    } else {
        width = dexGetInstrWidthAbs(widths, INST_INST(insns[0]));
    }
    return width;
}
