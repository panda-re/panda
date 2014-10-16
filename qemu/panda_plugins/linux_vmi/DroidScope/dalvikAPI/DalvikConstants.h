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
 * @date 19 JAN 2012
 * Pretty much stolen from dalvik/vm/mterp/common/asm-constants.h
 *
 * Just used s/MTERP_CONST(/#define DS_/g and then s/,.+, (\d+)\)/ \1/g and variants to replace the names
 * Make sure they are applied in the right order, otherwise things might go weird
 */

#ifndef DALVIK_CONSTANTS_H
#define DALVIK_CONSTANTS_H

//we know that JIT is enabled so we defined this
#define DS_WITH_JIT

#define DS_sizeofGlobal_debuggerActive 1
#define DS_sizeofGlobal_activeProfilers 4

/* MterpGlue fields */
#define DS_offGlue_pc 0
#define DS_offGlue_fp 4
#define DS_offGlue_retval 8
#define DS_offGlue_method 16
#define DS_offGlue_methodClassDex 20
#define DS_offGlue_self 24
#define DS_offGlue_bailPtr 28
#define DS_offGlue_interpStackEnd 32
#define DS_offGlue_pSelfSuspendCount 36
#define DS_offGlue_cardTable 40
#define DS_offGlue_pDebuggerActive 44
#define DS_offGlue_pActiveProfilers 48
#define DS_offGlue_entryPoint 52
#if defined(DS_WITH_JIT)
#define DS_offGlue_pJitProfTable 60
#define DS_offGlue_jitState 64
#define DS_offGlue_jitResumeNPC 68
#define DS_offGlue_jitResumeDPC 72
#define DS_offGlue_jitThreshold 76
#define DS_offGlue_ppJitProfTable 80
#define DS_offGlue_icRechainCount 84
#endif
/* make sure all JValue union members are stored at the same offset */
#define DS_offGlue_retval_z 8
#define DS_offGlue_retval_i 8
#define DS_offGlue_retval_j 8
#define DS_offGlue_retval_l 8

/* DvmDex fields */
#define DS_offDvmDex_pResStrings 8
#define DS_offDvmDex_pResClasses 12
#define DS_offDvmDex_pResMethods 16
#define DS_offDvmDex_pResFields 20
#define DS_offDvmDex_pInterfaceCache 24

/* StackSaveArea fields */
#ifdef EASY_GDB
#define DS_offStackSaveArea_prevSave 0
#define DS_offStackSaveArea_prevFrame 4
#define DS_offStackSaveArea_savedPc 8
#define DS_offStackSaveArea_method 12
#define DS_offStackSaveArea_currentPc 16
#define DS_offStackSaveArea_localRefCookie 16
#define DS_offStackSaveArea_returnAddr 20
#define DS_sizeofStackSaveArea 24
#else
#define DS_offStackSaveArea_prevFrame 0
#define DS_offStackSaveArea_savedPc 4
#define DS_offStackSaveArea_method 8
#define DS_offStackSaveArea_currentPc 12
#define DS_offStackSaveArea_localRefCookie 12
#define DS_offStackSaveArea_returnAddr 16
#define DS_sizeofStackSaveArea 20
#endif

  /* ShadowSpace fields */
#if defined(DS_WITH_JIT) && defined(DS_WITH_SELF_VERIFICATION)
#define DS_offShadowSpace_startPC 0
#define DS_offShadowSpace_fp 4
#define DS_offShadowSpace_glue 8
#define DS_offShadowSpace_jitExitState 12
#define DS_offShadowSpace_svState 16
#define DS_offShadowSpace_shadowFP 24
#define DS_offShadowSpace_interpState 32
#endif

/* InstField fields */
#ifdef PROFILE_FIELD_ACCESS
#define DS_offInstField_byteOffset 24
#else
#define DS_offInstField_byteOffset 16
#endif

/* Field fields */
#define DS_offField_clazz 0
#define DS_offField_name 4

/* StaticField fields */
#ifdef PROFILE_FIELD_ACCESS
#define DS_offStaticField_value 24
#else
#define DS_offStaticField_value 16
#endif

/* Method fields */
#define DS_offMethod_clazz 0
#define DS_offMethod_accessFlags 4
#define DS_offMethod_methodIndex 8
#define DS_offMethod_registersSize 10
#define DS_offMethod_outsSize 12
#define DS_offMethod_name 16
#define DS_offMethod_insns 32
#define DS_offMethod_nativeFunc 40

/* InlineOperation fields -- code assumes "func" offset is zero, do not alter */
#define DS_offInlineOperation_func 0

/* Thread fields */
#define DS_offThread_stackOverflowed 36
#define DS_offThread_curFrame 40
#define DS_offThread_exception 44

#if defined(DS_WITH_JIT)
#define DS_offThread_inJitCodeCache 72
#if defined(DS_WITH_SELF_VERIFICATION)
#define DS_offThread_shadowSpace 76
#ifdef USE_INDIRECT_REF
#define DS_offThread_jniLocal_topCookie 80
#else
#define DS_offThread_jniLocal_topCookie 80
#endif
#else
#ifdef USE_INDIRECT_REF
#define DS_offThread_jniLocal_topCookie 76
#else
#define DS_offThread_jniLocal_topCookie 76
#endif
#endif
#else
#ifdef USE_INDIRECT_REF
#define DS_offThread_jniLocal_topCookie 72
#else
#define DS_offThread_jniLocal_topCookie 72
#endif
#endif

/* Object fields */
#define DS_offObject_clazz 0
#define DS_offObject_lock 4

/* Lock shape */
#define DS_LW_LOCK_OWNER_SHIFT 3
#define DS_LW_HASH_STATE_SHIFT 1

/* ArrayObject fields */
#define DS_offArrayObject_length 8
#ifdef MTERP_NO_UNALIGN_64
#define DS_offArrayObject_contents 16
#else
#define DS_offArrayObject_contents 12
#endif

/* String fields */
#define DS_STRING_FIELDOFF_VALUE 8
#define DS_STRING_FIELDOFF_HASHCODE 12
#define DS_STRING_FIELDOFF_OFFSET 16
#define DS_STRING_FIELDOFF_COUNT 20

#if defined(DS_WITH_JIT)
/*
 * Reasons for the non-chaining interpreter entry points
 * Enums defined in vm/Globals.h
 */
#define DS_kInlineCacheMiss 0
#define DS_kCallsiteInterpreted 1
#define DS_kSwitchOverflow 2
#define DS_kHeavyweightMonitor 3

/* Size of callee save area */
#define DS_JIT_CALLEE_SAVE_DOUBLE_COUNT 8
#endif

/* ClassObject fields */
#define DS_offClassObject_descriptor 24
#define DS_offClassObject_accessFlags 32
#define DS_offClassObject_pDvmDex 40
#define DS_offClassObject_status 44
#define DS_offClassObject_super 72
#define DS_offClassObject_vtableCount 112
#define DS_offClassObject_vtable 116

/* InterpEntry enumeration */
#define DS_sizeofClassStatus MTERP_SMALL_ENUM
#define DS_kInterpEntryInstr 0
#define DS_kInterpEntryReturn 1
#define DS_kInterpEntryThrow 2
#if defined(DS_WITH_JIT)
#define DS_kInterpEntryResume 3
#endif

#if defined(DS_WITH_JIT)
#define DS_kJitNot 0
#define DS_kJitTSelectRequest 1
#define DS_kJitTSelectRequestHot 2
#define DS_kJitSelfVerification 3
#define DS_kJitTSelect 4
#define DS_kJitTSelectEnd 5
#define DS_kJitSingleStep 6
#define DS_kJitSingleStepEnd 7
#define DS_kJitDone 8

#if defined(DS_WITH_SELF_VERIFICATION)
#define DS_kSVSIdle 0
#define DS_kSVSStart 1
#define DS_kSVSPunt 2
#define DS_kSVSSingleStep 3
#define DS_kSVSNoProfile 4
#define DS_kSVSTraceSelect 5
#define DS_kSVSNormal 6
#define DS_kSVSNoChain 7
#define DS_kSVSBackwardBranch 8
#define DS_kSVSDebugInterp 9
#endif
#endif

/* ClassStatus enumeration */
#define DS_sizeofClassStatus MTERP_SMALL_ENUM
#define DS_CLASS_INITIALIZED 7

/* MethodType enumeration */
#define DS_sizeofMethodType MTERP_SMALL_ENUM
#define DS_METHOD_DIRECT 1
#define DS_METHOD_STATIC 2
#define DS_METHOD_VIRTUAL 3
#define DS_METHOD_INTERFACE 4

/* ClassObject constants */
#define DS_ACC_PRIVATE         0x0002
#define DS_ACC_STATIC         0x0008
#define DS_ACC_NATIVE          0x0100
#define DS_ACC_INTERFACE       0x0200
#define DS_ACC_ABSTRACT        0x0400

/* flags for dvmMalloc */
#define DS_ALLOC_DONT_TRACK    0x01

/* for GC */
#define DS_GC_CARD_SHIFT 7

/* opcode number */
#define DS_OP_MOVE_EXCEPTION   0x0d

#endif//DALVIK_CONSTANTS_H
