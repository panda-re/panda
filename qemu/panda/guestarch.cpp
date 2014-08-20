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



/*
 * This file is responsible for implementing the architecture-specific details
 * for the taint processor, such as printing taint ops, and determining where in
 * the CPUState memory accesses are.
 */

#include <stdio.h>
#include <math.h>

extern "C" {
#include "cpu.h"
#include "config.h"
#include "dyngen-exec.h"
#include "qemu-common.h"
}

#include "guestarch.h"

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

uintptr_t eax_reg = (uintptr_t)NULL;
uintptr_t ecx_reg = (uintptr_t)NULL;
uintptr_t edx_reg = (uintptr_t)NULL;
uintptr_t ebx_reg = (uintptr_t)NULL;
uintptr_t esp_reg = (uintptr_t)NULL;
uintptr_t ebp_reg = (uintptr_t)NULL;
uintptr_t esi_reg = (uintptr_t)NULL;
uintptr_t edi_reg = (uintptr_t)NULL;
uintptr_t cc_op_reg = (uintptr_t)NULL;  //
uintptr_t cc_src_reg = (uintptr_t)NULL; // maybe we should remove these until
uintptr_t cc_dst_reg = (uintptr_t)NULL; // we need them
uintptr_t eip_reg = (uintptr_t)NULL;

void init_regs(void){
    eax_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EAX]);
    ecx_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_ECX]);
    edx_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EDX]);
    ebx_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EBX]);
    esp_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_ESP]);
    ebp_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EBP]);
    esi_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_ESI]);
    edi_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EDI]);
    cc_op_reg = (uintptr_t)env + offsetof(CPUX86State, cc_op);
    cc_src_reg = (uintptr_t)env + offsetof(CPUX86State, cc_src);
    cc_dst_reg = (uintptr_t)env + offsetof(CPUX86State, cc_dst);
    eip_reg = (uintptr_t)env + offsetof(CPUX86State, eip);
}

int get_cpustate_val(uintptr_t dynval){
    if (dynval < ((uintptr_t)env + offsetof(CPUX86State, eflags))){
        if (dynval == eax_reg){
            return R_EAX;
        }
        else if (dynval == ecx_reg){
            return R_ECX;
        }
        else if (dynval == edx_reg){
            return R_EDX;
        }
        else if (dynval == ebx_reg){
            return R_EBX;
        }
        else if (dynval == esp_reg){
            return R_ESP;
        }
        else if (dynval == ebp_reg){
            return R_EBP;
        }
        else if (dynval == esi_reg){
            return R_ESI;
        }
        else if (dynval == edi_reg){
            return R_EDI;
        }
        else if (dynval == cc_op_reg){
            return CC_OP_REG;
        }
        else if (dynval == cc_src_reg){
            return CC_SRC_REG;
        }
        else if (dynval == cc_dst_reg){
            return CC_DST_REG;
        }
        else if (dynval == eip_reg){
            return EIP_REG;
        }
        else {
            return -1; // error
        }
    }
    else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs)
                + (sizeof(XMMReg) * CPU_NB_REGS)))){
        // inside XMM regs
        // print the proper enum to be used by the trace analyzer

        // get XMM register
        int xmmreg =
            floor(((dynval - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0])))
            / sizeof(XMMReg)));
        // get offset within register
        int xmmoff =
            (dynval - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0]))) %
            sizeof(XMMReg);
        // get enum that can be be processed by trace analyzer
        int xmmenum = XMMREGS_0_0 + xmmreg*16 + xmmoff;

        return xmmenum;

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, ft0)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, ft0)
                + sizeof(floatx80)))){
        // inside ft0
        // print the proper enum to be used by the trace analyzer
        return (dynval - ((uintptr_t)env +
            offsetof(CPUX86State, ft0)) + FT0_0);

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)
                + sizeof(XMMReg)))){
        // inside xmm_t0
        // print the proper enum to be used by the trace analyzer
        return (dynval - ((uintptr_t)env +
            offsetof(CPUX86State, xmm_t0)) + XMM_T0_0);

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)
                + sizeof(MMXReg)))){
        // inside mmx_t0
        // print the proper enum to be used by the trace analyzer
        return (dynval - ((uintptr_t)env +
            offsetof(CPUX86State, mmx_t0)) + MMX_T0_0);

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, fpregs)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, fpregs)
                + (sizeof(FPReg) * 8)))){
        // inside FP regs
        // print the proper enum as seen above to be used by the trace analyzer

        // get FP register
        int fpreg =
            floor(((dynval - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) /
            sizeof(FPReg)));
        // get offset within register
        int fpoff =
            (dynval - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) %
            sizeof(FPReg);
        // get enum that can be be processed by trace analyzer
        int fpenum = FPREGS_0_0 + fpreg*10 + fpoff;

        return fpenum;
    }

    else {
        return -1; // irrelevant part of CPUstate
    }
}

void printreg(Addr *a){

    switch(a->val.gr){
        case R_EAX:
            printf("g_eax[%d]", a->off);
            break;
        case R_ECX:
            printf("g_ecx[%d]", a->off);
            break;
        case R_EDX:
            printf("g_edx[%d]", a->off);
            break;
        case R_EBX:
            printf("g_ebx[%d]", a->off);
            break;
        case R_ESP:
            printf("g_esp[%d]", a->off);
            break;
        case R_EBP:
            printf("g_ebp[%d]", a->off);
            break;
        case R_ESI:
            printf("g_esi[%d]", a->off);
            break;
        case R_EDI:
            printf("g_edi[%d]", a->off);
            break;
        case CC_OP_REG:
            printf("g_cc_op[%d]", a->off);
            break;
        case CC_SRC_REG:
            printf("g_cc_src[%d]", a->off);
            break;
        case CC_DST_REG:
            printf("g_cc_dst[%d]", a->off);
            break;
        case EIP_REG:
            printf("g_eip[%d]", a->off);
            break;
        default:
            assert(1==0);
    }
}

void printspec(Addr *a){
    if ((a->val.gs >= FT0_0) && (a->val.gs < XMM_T0_0)){
        printf("g_ft0[%d]", a->off);
    }
    else if ((a->val.gs >= XMM_T0_0) && (a->val.gs < MMX_T0_0)){
        printf("g_xmm_t0[%d]", a->off);
    }
    else if ((a->val.gs >= MMX_T0_0) && (a->val.gs < FPREGS_0_0)){
        printf("g_mmx_t0[%d]", a->off);
    }
    else if ((a->val.gs >= FPREGS_0_0) && (a->val.gs < XMMREGS_0_0)){
        int fpreg = (a->val.gs - FPREGS_0_0) / 10; // fpregs are 10 bytes
        printf("g_st%d[%d]", fpreg, a->off);
    }
    else if ((a->val.gs >= XMMREGS_0_0) && (a->val.gs <= XMMREGS_7_15)){
        int fpreg = (a->val.gs - XMMREGS_0_0) / 16; // xmm regs are 16 bytes
        printf("g_xmm%d[%d]", fpreg, a->off);
    }
    else {
        assert(1==0);
    }
}

#endif

#ifdef TARGET_X86_64

uintptr_t rax_reg = (uintptr_t)NULL;
uintptr_t rcx_reg = (uintptr_t)NULL;
uintptr_t rdx_reg = (uintptr_t)NULL;
uintptr_t rbx_reg = (uintptr_t)NULL;
uintptr_t rsp_reg = (uintptr_t)NULL;
uintptr_t rbp_reg = (uintptr_t)NULL;
uintptr_t rsi_reg = (uintptr_t)NULL;
uintptr_t rdi_reg = (uintptr_t)NULL;
uintptr_t r8_reg = (uintptr_t)NULL;
uintptr_t r9_reg = (uintptr_t)NULL;
uintptr_t r10_reg = (uintptr_t)NULL;
uintptr_t r11_reg = (uintptr_t)NULL;
uintptr_t r12_reg = (uintptr_t)NULL;
uintptr_t r13_reg = (uintptr_t)NULL;
uintptr_t r14_reg = (uintptr_t)NULL;
uintptr_t r15_reg = (uintptr_t)NULL;
uintptr_t cc_op_reg = (uintptr_t)NULL;  //
uintptr_t cc_src_reg = (uintptr_t)NULL; // maybe we should remove these until
uintptr_t cc_dst_reg = (uintptr_t)NULL; // we need them
uintptr_t rip_reg = (uintptr_t)NULL;

void init_regs(void){
    rax_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EAX]);
    rcx_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_ECX]);
    rdx_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EDX]);
    rbx_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EBX]);
    rsp_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_ESP]);
    rbp_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EBP]);
    rsi_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_ESI]);
    rdi_reg = (uintptr_t)env + offsetof(CPUX86State, regs[R_EDI]);
    r8_reg = (uintptr_t)env + offsetof(CPUX86State, regs[8]);
    r9_reg = (uintptr_t)env + offsetof(CPUX86State, regs[9]);
    r10_reg = (uintptr_t)env + offsetof(CPUX86State, regs[10]);
    r11_reg = (uintptr_t)env + offsetof(CPUX86State, regs[11]);
    r12_reg = (uintptr_t)env + offsetof(CPUX86State, regs[12]);
    r13_reg = (uintptr_t)env + offsetof(CPUX86State, regs[13]);
    r14_reg = (uintptr_t)env + offsetof(CPUX86State, regs[14]);
    r15_reg = (uintptr_t)env + offsetof(CPUX86State, regs[15]);
    cc_op_reg = (uintptr_t)env + offsetof(CPUX86State, cc_op);
    cc_src_reg = (uintptr_t)env + offsetof(CPUX86State, cc_src);
    cc_dst_reg = (uintptr_t)env + offsetof(CPUX86State, cc_dst);
    rip_reg = (uintptr_t)env + offsetof(CPUX86State, eip);
}

int get_cpustate_val(uintptr_t dynval){
    if (dynval < ((uintptr_t)env + offsetof(CPUX86State, eflags))){
        if (dynval == rax_reg){
            return R_EAX;
        }
        else if (dynval == rcx_reg){
            return R_ECX;
        }
        else if (dynval == rdx_reg){
            return R_EDX;
        }
        else if (dynval == rbx_reg){
            return R_EBX;
        }
        else if (dynval == rsp_reg){
            return R_ESP;
        }
        else if (dynval == rbp_reg){
            return R_EBP;
        }
        else if (dynval == rsi_reg){
            return R_ESI;
        }
        else if (dynval == rdi_reg){
            return R_EDI;
        }
        else if (dynval == r8_reg){
            return R8;
        }
        else if (dynval == r9_reg){
            return R9;
        }
        else if (dynval == r10_reg){
            return R10;
        }
        else if (dynval == r11_reg){
            return R11;
        }
        else if (dynval == r12_reg){
            return R12;
        }
        else if (dynval == r13_reg){
            return R13;
        }
        else if (dynval == r14_reg){
            return R14;
        }
        else if (dynval == r15_reg){
            return R15;
        }
        else if (dynval == cc_op_reg){
            return CC_OP_REG;
        }
        else if (dynval == cc_src_reg){
            return CC_SRC_REG;
        }
        else if (dynval == cc_dst_reg){
            return CC_DST_REG;
        }
        else if (dynval == rip_reg){
            return RIP_REG;
        }
        else {
            return -1; // error
        }
    }
    else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs[0])))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs[0])
                + (sizeof(XMMReg) * CPU_NB_REGS)))){
        // inside XMM regs
        // print the proper enum to be used by the trace analyzer

        // get XMM register
        int xmmreg =
            floor(((dynval - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0])))
            / sizeof(XMMReg)));
        // get offset within register
        int xmmoff =
            (dynval - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0]))) %
            sizeof(XMMReg);
        // get enum that can be be processed by trace analyzer
        int xmmenum = XMMREGS_0_0 + xmmreg*16 + xmmoff;

        return xmmenum;

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, ft0)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, ft0)
                + sizeof(floatx80)))){
        // inside ft0
        // print the proper enum to be used by the trace analyzer
        return (dynval - ((uintptr_t)env +
            offsetof(CPUX86State, ft0)) + FT0_0);

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)
                + sizeof(XMMReg)))){
        // inside xmm_t0
        // print the proper enum to be used by the trace analyzer
        return (dynval - ((uintptr_t)env +
            offsetof(CPUX86State, xmm_t0)) + XMM_T0_0);

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)
                + sizeof(MMXReg)))){
        // inside mmx_t0
        // print the proper enum to be used by the trace analyzer
        return (dynval - ((uintptr_t)env +
            offsetof(CPUX86State, mmx_t0)) + MMX_T0_0);

    } else if ((dynval >= (((uintptr_t)env) + offsetof(CPUX86State, fpregs[0])))
            && (dynval < (((uintptr_t)env) + offsetof(CPUX86State, fpregs[0])
                + (sizeof(FPReg) * 8)))){
        // inside FP regs
        // print the proper enum as seen above to be used by the trace analyzer

        // get FP register
        int fpreg =
            floor(((dynval - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) /
            sizeof(FPReg)));
        // get offset within register
        int fpoff =
            (dynval - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) %
            sizeof(FPReg);
        // get enum that can be be processed by trace analyzer
        int fpenum = FPREGS_0_0 + fpreg*10 + fpoff;

        return fpenum;
    }

    else {
        return -1; // irrelevant part of CPUstate
    }
}

void printreg(Addr *a){

    switch(a->val.gr){
        case R_EAX:
            printf("g_rax[%d]", a->off);
            break;
        case R_ECX:
            printf("g_rcx[%d]", a->off);
            break;
        case R_EDX:
            printf("g_rdx[%d]", a->off);
            break;
        case R_EBX:
            printf("g_rbx[%d]", a->off);
            break;
        case R_ESP:
            printf("g_rsp[%d]", a->off);
            break;
        case R_EBP:
            printf("g_rbp[%d]", a->off);
            break;
        case R_ESI:
            printf("g_rsi[%d]", a->off);
            break;
        case R_EDI:
            printf("g_rdi[%d]", a->off);
            break;
        case R8:
            printf("g_r8[%d]", a->off);
            break;
        case R9:
            printf("g_r9[%d]", a->off);
            break;
        case R10:
            printf("g_r10[%d]", a->off);
            break;
        case R11:
            printf("g_r11[%d]", a->off);
            break;
        case R12:
            printf("g_r12[%d]", a->off);
            break;
        case R13:
            printf("g_r13[%d]", a->off);
            break;
        case R14:
            printf("g_r14[%d]", a->off);
            break;
        case R15:
            printf("g_r15[%d]", a->off);
            break;
        case CC_OP_REG:
            printf("g_cc_op[%d]", a->off);
            break;
        case CC_SRC_REG:
            printf("g_cc_src[%d]", a->off);
            break;
        case CC_DST_REG:
            printf("g_cc_dst[%d]", a->off);
            break;
        case RIP_REG:
            printf("g_rip[%d]", a->off);
            break;
        default:
            assert(1==0);
    }
}

void printspec(Addr *a){
    if ((a->val.gs >= FT0_0) && (a->val.gs < XMM_T0_0)){
        printf("g_ft0[%d]", a->off);
    }
    else if ((a->val.gs >= XMM_T0_0) && (a->val.gs < MMX_T0_0)){
        printf("g_xmm_t0[%d]", a->off);
    }
    else if ((a->val.gs >= MMX_T0_0) && (a->val.gs < FPREGS_0_0)){
        printf("g_mmx_t0[%d]", a->off);
    }
    else if ((a->val.gs >= FPREGS_0_0) && (a->val.gs < XMMREGS_0_0)){
        int fpreg = (a->val.gs - FPREGS_0_0) / 10; // fpregs are 10 bytes
        printf("g_st%d[%d]", fpreg, a->off);
    }
    else if ((a->val.gs >= XMMREGS_0_0) && (a->val.gs <= XMMREGS_15_15)){
        int fpreg = (a->val.gs - XMMREGS_0_0) / 16; // xmm regs are 16 bytes
        printf("g_xmm%d[%d]", fpreg, a->off);
    }
    else {
        assert(1==0);
    }
}

#endif

#ifdef TARGET_ARM

uintptr_t r0_reg = (uintptr_t)NULL;
uintptr_t r1_reg = (uintptr_t)NULL;
uintptr_t r2_reg = (uintptr_t)NULL;
uintptr_t r3_reg = (uintptr_t)NULL;
uintptr_t r4_reg = (uintptr_t)NULL;
uintptr_t r5_reg = (uintptr_t)NULL;
uintptr_t r6_reg = (uintptr_t)NULL;
uintptr_t r7_reg = (uintptr_t)NULL;
uintptr_t r8_reg = (uintptr_t)NULL;
uintptr_t r9_reg = (uintptr_t)NULL;
uintptr_t r10_reg = (uintptr_t)NULL;
uintptr_t r11_reg = (uintptr_t)NULL;
uintptr_t r12_reg = (uintptr_t)NULL;
uintptr_t r13_reg = (uintptr_t)NULL;
uintptr_t r14_reg = (uintptr_t)NULL;
uintptr_t r15_reg = (uintptr_t)NULL;

void init_regs(void){
    r0_reg = (uintptr_t)env + offsetof(CPUARMState, regs[0]);
    r1_reg = (uintptr_t)env + offsetof(CPUARMState, regs[1]);
    r2_reg = (uintptr_t)env + offsetof(CPUARMState, regs[2]);
    r3_reg = (uintptr_t)env + offsetof(CPUARMState, regs[3]);
    r4_reg = (uintptr_t)env + offsetof(CPUARMState, regs[4]);
    r5_reg = (uintptr_t)env + offsetof(CPUARMState, regs[5]);
    r6_reg = (uintptr_t)env + offsetof(CPUARMState, regs[6]);
    r7_reg = (uintptr_t)env + offsetof(CPUARMState, regs[7]);
    r8_reg = (uintptr_t)env + offsetof(CPUARMState, regs[8]);
    r9_reg = (uintptr_t)env + offsetof(CPUARMState, regs[9]);
    r10_reg = (uintptr_t)env + offsetof(CPUARMState, regs[10]);
    r11_reg = (uintptr_t)env + offsetof(CPUARMState, regs[11]);
    r12_reg = (uintptr_t)env + offsetof(CPUARMState, regs[12]);
    r13_reg = (uintptr_t)env + offsetof(CPUARMState, regs[13]);
    r14_reg = (uintptr_t)env + offsetof(CPUARMState, regs[14]);
    r15_reg = (uintptr_t)env + offsetof(CPUARMState, regs[15]);
}

int get_cpustate_val(uintptr_t dynval){
    if (dynval == r0_reg){
        return 0;
    }
    else if (dynval == r1_reg){
        return 1;
    }
    else if (dynval == r2_reg){
        return 2;
    }
    else if (dynval == r3_reg){
        return 3;
    }
    else if (dynval == r4_reg){
        return 4;
    }
    else if (dynval == r5_reg){
        return 5;
    }
    else if (dynval == r6_reg){
        return 6;
    }
    else if (dynval == r7_reg){
        return 7;
    }
    else if (dynval == r8_reg){
        return 8;
    }
    else if (dynval == r9_reg){
        return 9;
    }
    else if (dynval == r10_reg){
        return 10;
    }
    else if (dynval == r11_reg){
        return 11;
    }
    else if (dynval == r12_reg){
        return 12;
    }
    else if (dynval == r13_reg){
        return 13;
    }
    else if (dynval == r14_reg){
        return 14;
    }
    else if (dynval == r15_reg){
        return 15;
    }
    else {
        return -1; // irrelevant part of CPUstate
    }
}

void printreg(Addr *a){
    switch(a->val.gr){
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
            printf("g_r%d[%d]", (int)a->val.gr, a->off);
            break;
        case 15:
            printf("g_pc[%d]", a->off);
            break;
        default:
            assert(1==0);
    }
}

void printspec(Addr *a){}

#endif

/*
void guestStoreTaint(LAddr localSrc, GReg guestDst, int len,
    TaintOpBuffer *buf){
    struct addr_struct src = {(AddrType) 0,{0},0,(AddrFlag) 0};
    struct addr_struct dst = {(AddrType) 0,{0},0,(AddrFlag) 0};
    TaintOp op;
    memset(&op, 0, sizeof(TaintOp));
    op.typ = COPYOP;
    src.typ = LADDR;
    src.val.la = localSrc;
    dst.typ = GREG;
    dst.val.gr = guestDst;
    int i;
    for (i = 0; i < len; i++){
        dst.off = i;
        src.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(buf, &op);
    }
}

void guestLoadTaint(GReg guestSrc, LAddr localDst, int len, TaintOpBuffer *buf){
    struct addr_struct src = {(AddrType) 0,{0},0,(AddrFlag) 0};
    struct addr_struct dst = {(AddrType) 0,{0},0,(AddrFlag) 0};
    TaintOp op;
    memset(&op, 0, sizeof(TaintOp));
    op.typ = COPYOP;
    src.typ = GREG;
    src.val.gr = guestSrc;
    dst.typ = LADDR;
    dst.val.la = localDst;
    int i;
    for (i = 0; i < len; i++){
        dst.off = i;
        src.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(buf, &op);
    }
}

void guestDeleteTaint(GReg guestDst, int len, TaintOpBuffer *buf){
    struct addr_struct dst = {(AddrType) 0,{0},0, (AddrFlag) 0};
    TaintOp op;
    memset(&op, 0, sizeof(TaintOp));
    op.typ = DELETEOP;
    dst.typ = GREG;
    dst.val.gr = guestDst;
    int i;
    for (i = 0; i < len; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(buf, &op);
    }
}
*/

