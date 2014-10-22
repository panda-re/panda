/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */



/*
 * XXX
 * XXX Note: changing this file could very easily break other code that uses it.
 * XXX
 */



#ifndef GUESTARCH_H
#define GUESTARCH_H

extern "C" {
#include "cpu.h"
}

//#include "../panda_plugins/taint/taint_processor.h"

#include "panda_addr.h"

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

extern uintptr_t eax_reg;
extern uintptr_t ecx_reg;
extern uintptr_t edx_reg;
extern uintptr_t ebx_reg;
extern uintptr_t esp_reg;
extern uintptr_t ebp_reg;
extern uintptr_t esi_reg;
extern uintptr_t edi_reg;
extern uintptr_t cc_op_reg;  //
extern uintptr_t cc_src_reg; // maybe we should remove these until we need them
extern uintptr_t cc_dst_reg; //
extern uintptr_t eip_reg;

/*
 * These continue #defines after general purpose regs in cpu.h
 */
#define CC_OP_REG 8
#define CC_SRC_REG 9
#define CC_DST_REG 10
#define EIP_REG 11

/*
 * We assume that this enum starts right after guest registers.
 *
 * XMM and MMX registers can be accessed at offsets inside of them, so log the
 * specific byte accessed for these registers.  XMM registers are 16 bytes.
 * Floating point registers are 10 bytes.  XMM_T0 and MMX_T0 don't correspond to
 * actual hardware, but they are a part of the CPUState.  Same with FT0.
 */
enum SpecAddrs {
    FT0_0 = 12,
    FT0_1,
    FT0_2,
    FT0_3,
    FT0_4,
    FT0_5,
    FT0_6,
    FT0_7,
    FT0_8,
    FT0_9,
    XMM_T0_0,
    XMM_T0_1,
    XMM_T0_2,
    XMM_T0_3,
    XMM_T0_4,
    XMM_T0_5,
    XMM_T0_6,
    XMM_T0_7,
    XMM_T0_8,
    XMM_T0_9,
    XMM_T0_10,
    XMM_T0_11,
    XMM_T0_12,
    XMM_T0_13,
    XMM_T0_14,
    XMM_T0_15,
    MMX_T0_0,
    MMX_T0_1,
    MMX_T0_2,
    MMX_T0_3,
    MMX_T0_4,
    MMX_T0_5,
    MMX_T0_6,
    MMX_T0_7,
    FPREGS_0_0,
    FPREGS_0_1,
    FPREGS_0_2,
    FPREGS_0_3,
    FPREGS_0_4,
    FPREGS_0_5,
    FPREGS_0_6,
    FPREGS_0_7,
    FPREGS_0_8,
    FPREGS_0_9,
    FPREGS_1_0,
    FPREGS_1_1,
    FPREGS_1_2,
    FPREGS_1_3,
    FPREGS_1_4,
    FPREGS_1_5,
    FPREGS_1_6,
    FPREGS_1_7,
    FPREGS_1_8,
    FPREGS_1_9,
    FPREGS_2_0,
    FPREGS_2_1,
    FPREGS_2_2,
    FPREGS_2_3,
    FPREGS_2_4,
    FPREGS_2_5,
    FPREGS_2_6,
    FPREGS_2_7,
    FPREGS_2_8,
    FPREGS_2_9,
    FPREGS_3_0,
    FPREGS_3_1,
    FPREGS_3_2,
    FPREGS_3_3,
    FPREGS_3_4,
    FPREGS_3_5,
    FPREGS_3_6,
    FPREGS_3_7,
    FPREGS_3_8,
    FPREGS_3_9,
    FPREGS_4_0,
    FPREGS_4_1,
    FPREGS_4_2,
    FPREGS_4_3,
    FPREGS_4_4,
    FPREGS_4_5,
    FPREGS_4_6,
    FPREGS_4_7,
    FPREGS_4_8,
    FPREGS_4_9,
    FPREGS_5_0,
    FPREGS_5_1,
    FPREGS_5_2,
    FPREGS_5_3,
    FPREGS_5_4,
    FPREGS_5_5,
    FPREGS_5_6,
    FPREGS_5_7,
    FPREGS_5_8,
    FPREGS_5_9,
    FPREGS_6_0,
    FPREGS_6_1,
    FPREGS_6_2,
    FPREGS_6_3,
    FPREGS_6_4,
    FPREGS_6_5,
    FPREGS_6_6,
    FPREGS_6_7,
    FPREGS_6_8,
    FPREGS_6_9,
    FPREGS_7_0,
    FPREGS_7_1,
    FPREGS_7_2,
    FPREGS_7_3,
    FPREGS_7_4,
    FPREGS_7_5,
    FPREGS_7_6,
    FPREGS_7_7,
    FPREGS_7_8,
    FPREGS_7_9,
    XMMREGS_0_0,
    XMMREGS_0_1,
    XMMREGS_0_2,
    XMMREGS_0_3,
    XMMREGS_0_4,
    XMMREGS_0_5,
    XMMREGS_0_6,
    XMMREGS_0_7,
    XMMREGS_0_8,
    XMMREGS_0_9,
    XMMREGS_0_10,
    XMMREGS_0_11,
    XMMREGS_0_12,
    XMMREGS_0_13,
    XMMREGS_0_14,
    XMMREGS_0_15,
    XMMREGS_1_0,
    XMMREGS_1_1,
    XMMREGS_1_2,
    XMMREGS_1_3,
    XMMREGS_1_4,
    XMMREGS_1_5,
    XMMREGS_1_6,
    XMMREGS_1_7,
    XMMREGS_1_8,
    XMMREGS_1_9,
    XMMREGS_1_10,
    XMMREGS_1_11,
    XMMREGS_1_12,
    XMMREGS_1_13,
    XMMREGS_1_14,
    XMMREGS_1_15,
    XMMREGS_2_0,
    XMMREGS_2_1,
    XMMREGS_2_2,
    XMMREGS_2_3,
    XMMREGS_2_4,
    XMMREGS_2_5,
    XMMREGS_2_6,
    XMMREGS_2_7,
    XMMREGS_2_8,
    XMMREGS_2_9,
    XMMREGS_2_10,
    XMMREGS_2_11,
    XMMREGS_2_12,
    XMMREGS_2_13,
    XMMREGS_2_14,
    XMMREGS_2_15,
    XMMREGS_3_0,
    XMMREGS_3_1,
    XMMREGS_3_2,
    XMMREGS_3_3,
    XMMREGS_3_4,
    XMMREGS_3_5,
    XMMREGS_3_6,
    XMMREGS_3_7,
    XMMREGS_3_8,
    XMMREGS_3_9,
    XMMREGS_3_10,
    XMMREGS_3_11,
    XMMREGS_3_12,
    XMMREGS_3_13,
    XMMREGS_3_14,
    XMMREGS_3_15,
    XMMREGS_4_0,
    XMMREGS_4_1,
    XMMREGS_4_2,
    XMMREGS_4_3,
    XMMREGS_4_4,
    XMMREGS_4_5,
    XMMREGS_4_6,
    XMMREGS_4_7,
    XMMREGS_4_8,
    XMMREGS_4_9,
    XMMREGS_4_10,
    XMMREGS_4_11,
    XMMREGS_4_12,
    XMMREGS_4_13,
    XMMREGS_4_14,
    XMMREGS_4_15,
    XMMREGS_5_0,
    XMMREGS_5_1,
    XMMREGS_5_2,
    XMMREGS_5_3,
    XMMREGS_5_4,
    XMMREGS_5_5,
    XMMREGS_5_6,
    XMMREGS_5_7,
    XMMREGS_5_8,
    XMMREGS_5_9,
    XMMREGS_5_10,
    XMMREGS_5_11,
    XMMREGS_5_12,
    XMMREGS_5_13,
    XMMREGS_5_14,
    XMMREGS_5_15,
    XMMREGS_6_0,
    XMMREGS_6_1,
    XMMREGS_6_2,
    XMMREGS_6_3,
    XMMREGS_6_4,
    XMMREGS_6_5,
    XMMREGS_6_6,
    XMMREGS_6_7,
    XMMREGS_6_8,
    XMMREGS_6_9,
    XMMREGS_6_10,
    XMMREGS_6_11,
    XMMREGS_6_12,
    XMMREGS_6_13,
    XMMREGS_6_14,
    XMMREGS_6_15,
    XMMREGS_7_0,
    XMMREGS_7_1,
    XMMREGS_7_2,
    XMMREGS_7_3,
    XMMREGS_7_4,
    XMMREGS_7_5,
    XMMREGS_7_6,
    XMMREGS_7_7,
    XMMREGS_7_8,
    XMMREGS_7_9,
    XMMREGS_7_10,
    XMMREGS_7_11,
    XMMREGS_7_12,
    XMMREGS_7_13,
    XMMREGS_7_14,
    XMMREGS_7_15
};

#define NUMREGS 12
#define NUMSPECADDRS (XMMREGS_7_15-FT0_0)
#define WORDSIZE 4
#define LENDIAN

#endif // TARGET_I386

#ifdef TARGET_X86_64

extern uintptr_t rax_reg;
extern uintptr_t rcx_reg;
extern uintptr_t rdx_reg;
extern uintptr_t rbx_reg;
extern uintptr_t rsp_reg;
extern uintptr_t rbp_reg;
extern uintptr_t rsi_reg;
extern uintptr_t rdi_reg;
extern uintptr_t r8_reg;
extern uintptr_t r9_reg;
extern uintptr_t r10_reg;
extern uintptr_t r11_reg;
extern uintptr_t r12_reg;
extern uintptr_t r13_reg;
extern uintptr_t r14_reg;
extern uintptr_t r15_reg;
extern uintptr_t cc_op_reg;  //
extern uintptr_t cc_src_reg; // maybe we should remove these until we need them
extern uintptr_t cc_dst_reg; //
extern uintptr_t rip_reg;

/*
 * These continue #defines after general purpose regs in cpu.h
 */
#define R8 8
#define R9 9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15
#define CC_OP_REG 16
#define CC_SRC_REG 17
#define CC_DST_REG 18
#define RIP_REG 19

/*
 * We assume that this enum starts right after guest registers.
 *
 * XMM and MMX registers can be accessed at offsets inside of them, so log the
 * specific byte accessed for these registers.  XMM registers are 16 bytes.
 * Floating point registers are 10 bytes.  XMM_T0 and MMX_T0 don't correspond to
 * actual hardware, but they are a part of the CPUState.  Same with FT0.
 */
enum SpecAddrs {
    FT0_0 = 20,
    FT0_1,
    FT0_2,
    FT0_3,
    FT0_4,
    FT0_5,
    FT0_6,
    FT0_7,
    FT0_8,
    FT0_9,
    XMM_T0_0,
    XMM_T0_1,
    XMM_T0_2,
    XMM_T0_3,
    XMM_T0_4,
    XMM_T0_5,
    XMM_T0_6,
    XMM_T0_7,
    XMM_T0_8,
    XMM_T0_9,
    XMM_T0_10,
    XMM_T0_11,
    XMM_T0_12,
    XMM_T0_13,
    XMM_T0_14,
    XMM_T0_15,
    MMX_T0_0,
    MMX_T0_1,
    MMX_T0_2,
    MMX_T0_3,
    MMX_T0_4,
    MMX_T0_5,
    MMX_T0_6,
    MMX_T0_7,
    FPREGS_0_0,
    FPREGS_0_1,
    FPREGS_0_2,
    FPREGS_0_3,
    FPREGS_0_4,
    FPREGS_0_5,
    FPREGS_0_6,
    FPREGS_0_7,
    FPREGS_0_8,
    FPREGS_0_9,
    FPREGS_1_0,
    FPREGS_1_1,
    FPREGS_1_2,
    FPREGS_1_3,
    FPREGS_1_4,
    FPREGS_1_5,
    FPREGS_1_6,
    FPREGS_1_7,
    FPREGS_1_8,
    FPREGS_1_9,
    FPREGS_2_0,
    FPREGS_2_1,
    FPREGS_2_2,
    FPREGS_2_3,
    FPREGS_2_4,
    FPREGS_2_5,
    FPREGS_2_6,
    FPREGS_2_7,
    FPREGS_2_8,
    FPREGS_2_9,
    FPREGS_3_0,
    FPREGS_3_1,
    FPREGS_3_2,
    FPREGS_3_3,
    FPREGS_3_4,
    FPREGS_3_5,
    FPREGS_3_6,
    FPREGS_3_7,
    FPREGS_3_8,
    FPREGS_3_9,
    FPREGS_4_0,
    FPREGS_4_1,
    FPREGS_4_2,
    FPREGS_4_3,
    FPREGS_4_4,
    FPREGS_4_5,
    FPREGS_4_6,
    FPREGS_4_7,
    FPREGS_4_8,
    FPREGS_4_9,
    FPREGS_5_0,
    FPREGS_5_1,
    FPREGS_5_2,
    FPREGS_5_3,
    FPREGS_5_4,
    FPREGS_5_5,
    FPREGS_5_6,
    FPREGS_5_7,
    FPREGS_5_8,
    FPREGS_5_9,
    FPREGS_6_0,
    FPREGS_6_1,
    FPREGS_6_2,
    FPREGS_6_3,
    FPREGS_6_4,
    FPREGS_6_5,
    FPREGS_6_6,
    FPREGS_6_7,
    FPREGS_6_8,
    FPREGS_6_9,
    FPREGS_7_0,
    FPREGS_7_1,
    FPREGS_7_2,
    FPREGS_7_3,
    FPREGS_7_4,
    FPREGS_7_5,
    FPREGS_7_6,
    FPREGS_7_7,
    FPREGS_7_8,
    FPREGS_7_9,
    XMMREGS_0_0,
    XMMREGS_0_1,
    XMMREGS_0_2,
    XMMREGS_0_3,
    XMMREGS_0_4,
    XMMREGS_0_5,
    XMMREGS_0_6,
    XMMREGS_0_7,
    XMMREGS_0_8,
    XMMREGS_0_9,
    XMMREGS_0_10,
    XMMREGS_0_11,
    XMMREGS_0_12,
    XMMREGS_0_13,
    XMMREGS_0_14,
    XMMREGS_0_15,
    XMMREGS_1_0,
    XMMREGS_1_1,
    XMMREGS_1_2,
    XMMREGS_1_3,
    XMMREGS_1_4,
    XMMREGS_1_5,
    XMMREGS_1_6,
    XMMREGS_1_7,
    XMMREGS_1_8,
    XMMREGS_1_9,
    XMMREGS_1_10,
    XMMREGS_1_11,
    XMMREGS_1_12,
    XMMREGS_1_13,
    XMMREGS_1_14,
    XMMREGS_1_15,
    XMMREGS_2_0,
    XMMREGS_2_1,
    XMMREGS_2_2,
    XMMREGS_2_3,
    XMMREGS_2_4,
    XMMREGS_2_5,
    XMMREGS_2_6,
    XMMREGS_2_7,
    XMMREGS_2_8,
    XMMREGS_2_9,
    XMMREGS_2_10,
    XMMREGS_2_11,
    XMMREGS_2_12,
    XMMREGS_2_13,
    XMMREGS_2_14,
    XMMREGS_2_15,
    XMMREGS_3_0,
    XMMREGS_3_1,
    XMMREGS_3_2,
    XMMREGS_3_3,
    XMMREGS_3_4,
    XMMREGS_3_5,
    XMMREGS_3_6,
    XMMREGS_3_7,
    XMMREGS_3_8,
    XMMREGS_3_9,
    XMMREGS_3_10,
    XMMREGS_3_11,
    XMMREGS_3_12,
    XMMREGS_3_13,
    XMMREGS_3_14,
    XMMREGS_3_15,
    XMMREGS_4_0,
    XMMREGS_4_1,
    XMMREGS_4_2,
    XMMREGS_4_3,
    XMMREGS_4_4,
    XMMREGS_4_5,
    XMMREGS_4_6,
    XMMREGS_4_7,
    XMMREGS_4_8,
    XMMREGS_4_9,
    XMMREGS_4_10,
    XMMREGS_4_11,
    XMMREGS_4_12,
    XMMREGS_4_13,
    XMMREGS_4_14,
    XMMREGS_4_15,
    XMMREGS_5_0,
    XMMREGS_5_1,
    XMMREGS_5_2,
    XMMREGS_5_3,
    XMMREGS_5_4,
    XMMREGS_5_5,
    XMMREGS_5_6,
    XMMREGS_5_7,
    XMMREGS_5_8,
    XMMREGS_5_9,
    XMMREGS_5_10,
    XMMREGS_5_11,
    XMMREGS_5_12,
    XMMREGS_5_13,
    XMMREGS_5_14,
    XMMREGS_5_15,
    XMMREGS_6_0,
    XMMREGS_6_1,
    XMMREGS_6_2,
    XMMREGS_6_3,
    XMMREGS_6_4,
    XMMREGS_6_5,
    XMMREGS_6_6,
    XMMREGS_6_7,
    XMMREGS_6_8,
    XMMREGS_6_9,
    XMMREGS_6_10,
    XMMREGS_6_11,
    XMMREGS_6_12,
    XMMREGS_6_13,
    XMMREGS_6_14,
    XMMREGS_6_15,
    XMMREGS_7_0,
    XMMREGS_7_1,
    XMMREGS_7_2,
    XMMREGS_7_3,
    XMMREGS_7_4,
    XMMREGS_7_5,
    XMMREGS_7_6,
    XMMREGS_7_7,
    XMMREGS_7_8,
    XMMREGS_7_9,
    XMMREGS_7_10,
    XMMREGS_7_11,
    XMMREGS_7_12,
    XMMREGS_7_13,
    XMMREGS_7_14,
    XMMREGS_7_15,
    XMMREGS_8_0,
    XMMREGS_8_1,
    XMMREGS_8_2,
    XMMREGS_8_3,
    XMMREGS_8_4,
    XMMREGS_8_5,
    XMMREGS_8_6,
    XMMREGS_8_7,
    XMMREGS_8_8,
    XMMREGS_8_9,
    XMMREGS_8_10,
    XMMREGS_8_11,
    XMMREGS_8_12,
    XMMREGS_8_13,
    XMMREGS_8_14,
    XMMREGS_8_15,
    XMMREGS_9_0,
    XMMREGS_9_1,
    XMMREGS_9_2,
    XMMREGS_9_3,
    XMMREGS_9_4,
    XMMREGS_9_5,
    XMMREGS_9_6,
    XMMREGS_9_7,
    XMMREGS_9_8,
    XMMREGS_9_9,
    XMMREGS_9_10,
    XMMREGS_9_11,
    XMMREGS_9_12,
    XMMREGS_9_13,
    XMMREGS_9_14,
    XMMREGS_9_15,
    XMMREGS_10_0,
    XMMREGS_10_1,
    XMMREGS_10_2,
    XMMREGS_10_3,
    XMMREGS_10_4,
    XMMREGS_10_5,
    XMMREGS_10_6,
    XMMREGS_10_7,
    XMMREGS_10_8,
    XMMREGS_10_9,
    XMMREGS_10_10,
    XMMREGS_10_11,
    XMMREGS_10_12,
    XMMREGS_10_13,
    XMMREGS_10_14,
    XMMREGS_10_15,
    XMMREGS_11_0,
    XMMREGS_11_1,
    XMMREGS_11_2,
    XMMREGS_11_3,
    XMMREGS_11_4,
    XMMREGS_11_5,
    XMMREGS_11_6,
    XMMREGS_11_7,
    XMMREGS_11_8,
    XMMREGS_11_9,
    XMMREGS_11_10,
    XMMREGS_11_11,
    XMMREGS_11_12,
    XMMREGS_11_13,
    XMMREGS_11_14,
    XMMREGS_11_15,
    XMMREGS_12_0,
    XMMREGS_12_1,
    XMMREGS_12_2,
    XMMREGS_12_3,
    XMMREGS_12_4,
    XMMREGS_12_5,
    XMMREGS_12_6,
    XMMREGS_12_7,
    XMMREGS_12_8,
    XMMREGS_12_9,
    XMMREGS_12_10,
    XMMREGS_12_11,
    XMMREGS_12_12,
    XMMREGS_12_13,
    XMMREGS_12_14,
    XMMREGS_12_15,
    XMMREGS_13_0,
    XMMREGS_13_1,
    XMMREGS_13_2,
    XMMREGS_13_3,
    XMMREGS_13_4,
    XMMREGS_13_5,
    XMMREGS_13_6,
    XMMREGS_13_7,
    XMMREGS_13_8,
    XMMREGS_13_9,
    XMMREGS_13_10,
    XMMREGS_13_11,
    XMMREGS_13_12,
    XMMREGS_13_13,
    XMMREGS_13_14,
    XMMREGS_13_15,
    XMMREGS_14_0,
    XMMREGS_14_1,
    XMMREGS_14_2,
    XMMREGS_14_3,
    XMMREGS_14_4,
    XMMREGS_14_5,
    XMMREGS_14_6,
    XMMREGS_14_7,
    XMMREGS_14_8,
    XMMREGS_14_9,
    XMMREGS_14_10,
    XMMREGS_14_11,
    XMMREGS_14_12,
    XMMREGS_14_13,
    XMMREGS_14_14,
    XMMREGS_14_15,
    XMMREGS_15_0,
    XMMREGS_15_1,
    XMMREGS_15_2,
    XMMREGS_15_3,
    XMMREGS_15_4,
    XMMREGS_15_5,
    XMMREGS_15_6,
    XMMREGS_15_7,
    XMMREGS_15_8,
    XMMREGS_15_9,
    XMMREGS_15_10,
    XMMREGS_15_11,
    XMMREGS_15_12,
    XMMREGS_15_13,
    XMMREGS_15_14,
    XMMREGS_15_15
};

#define NUMREGS 20
#define NUMSPECADDRS (XMMREGS_15_15-FT0_0)
#define WORDSIZE 8
#define LENDIAN

#endif

#ifdef TARGET_ARM

extern uintptr_t r0_reg;
extern uintptr_t r1_reg;
extern uintptr_t r2_reg;
extern uintptr_t r3_reg;
extern uintptr_t r4_reg;
extern uintptr_t r5_reg;
extern uintptr_t r6_reg;
extern uintptr_t r7_reg;
extern uintptr_t r8_reg;
extern uintptr_t r9_reg;
extern uintptr_t r10_reg;
extern uintptr_t r11_reg;
extern uintptr_t r12_reg;
extern uintptr_t r13_reg;
extern uintptr_t r14_reg;
extern uintptr_t r15_reg;

#define NUMREGS 16
#define NUMSPECADDRS 0
#define WORDSIZE 4
#define LENDIAN // FIXME: this is configurable in ARM

#endif

void init_regs(void);
int get_cpustate_val(uintptr_t dynval);

void fprintf_reg(Addr *a, FILE *fp);
void fprintf_spec(Addr *a, FILE *fp);

/*
void guestStoreTaint(LAddr localSrc, GReg guestDst, int len, TaintOpBuffer *buf);
void guestLoadTaint(GReg guestSrc, LAddr localDst, int len, TaintOpBuffer *buf);
void guestDeleteTaint(GReg guestDst, int len, TaintOpBuffer *buf);
*/
#endif

