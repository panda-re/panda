
#include "stdio.h"

#include "cpu.h"

#include "guestarch.h"

void printreg(Addr a){}
void printspec(Addr a){}

#if 0 // fix printing later

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

void printreg(Addr a){

    switch(a.val.gr){
        case R_EAX:
            printf("g_eax[%d]", a.off);
            break;
        case R_ECX:
            printf("g_ecx[%d]", a.off);
            break;
        case R_EDX:
            printf("g_edx[%d]", a.off);
            break;
        case R_EBX:
            printf("g_ebx[%d]", a.off);
            break;
        case R_ESP:
            printf("g_esp[%d]", a.off);
            break;
        case R_EBP:
            printf("g_ebp[%d]", a.off);
            break;
        case R_ESI:
            printf("g_esi[%d]", a.off);
            break;
        case R_EDI:
            printf("g_edi[%d]", a.off);
            break;
        case CC_OP:
            printf("g_cc_op[%d]", a.off);
            break;
        case CC_SRC:
            printf("g_cc_src[%d]", a.off);
            break;
        case CC_DST:
            printf("g_cc_dst[%d]", a.off);
            break;
        case EIP:
            printf("g_eip[%d]", a.off);
            break;
        default:
            assert(1==0);
    }
}

void printspec(Addr a){
    if ((a.val.gs >= XMM_T0_0) && (a.val.gs < MMX_T0_0)){
        printf("g_xmm_t0[%d]", a.off);
    }
    else if ((a.val.gs >= MMX_T0_0) && (a.val.gs < FPREGS_0_0)){
        printf("g_mmx_t0[%d]", a.off);
    }
    else if ((a.val.gs >= FPREGS_0_0) && (a.val.gs < XMMREGS_0_0)){
        int fpreg = (a.val.gs - FPREGS_0_0) / 10; // fpregs are 10 bytes
        printf("g_st%d[%d]", fpreg, a.off);
    }
    else if ((a.val.gs >= XMMREGS_0_0) && (a.val.gs <= XMMREGS_7_15)){
        int fpreg = (a.val.gs - XMMREGS_0_0) / 16; // xmm regs are 16 bytes
        printf("g_xmm%d[%d]", fpreg, a.off);
    }
    else {
        assert(1==0);
    }
}

#endif

#ifdef TARGET_X86_64

void printreg(Addr a){

    switch(a.val.gr){
        case R_RAX:
            printf("g_rax[%d]", a.off);
            break;
        case R_RCX:
            printf("g_rcx[%d]", a.off);
            break;
        case R_RDX:
            printf("g_rdx[%d]", a.off);
            break;
        case R_RBX:
            printf("g_rbx[%d]", a.off);
            break;
        case R_RSP:
            printf("g_rsp[%d]", a.off);
            break;
        case R_RBP:
            printf("g_rbp[%d]", a.off);
            break;
        case R_RSI:
            printf("g_rsi[%d]", a.off);
            break;
        case R_RDI:
            printf("g_rdi[%d]", a.off);
            break;
        case R8:
            printf("g_r8[%d]", a.off);
            break;
        case R9:
            printf("g_r9[%d]", a.off);
            break;
        case R10:
            printf("g_r10[%d]", a.off);
            break;
        case R11:
            printf("g_r11[%d]", a.off);
            break;
        case R12:
            printf("g_r12[%d]", a.off);
            break;
        case R13:
            printf("g_r13[%d]", a.off);
            break;
        case R14:
            printf("g_r14[%d]", a.off);
            break;
        case R15:
            printf("g_r15[%d]", a.off);
            break;
        case CC_OP:
            printf("g_cc_op[%d]", a.off);
            break;
        case CC_SRC:
            printf("g_cc_src[%d]", a.off);
            break;
        case CC_DST:
            printf("g_cc_dst[%d]", a.off);
            break;
        case RIP:
            printf("g_rip[%d]", a.off);
            break;
        default:
            assert(1==0);
    }
}

void printspec(Addr a){}

#endif

#ifdef TARGET_ARM

void printreg(Addr a){
    switch(a.val.gr){
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
            printf("g_r%d[%d]", (int)a.val.gr, a.off);
            break;
        case 15:
            printf("g_pc[%d]", a.off);
            break;
        default:
            assert(1==0);
    }
}

void printspec(Addr a){}

#endif
#endif

void guestStoreTaint(LAddr localSrc, GReg guestDst, int len,
    TaintOpBuffer *buf){
    struct addr_struct src = {0,{0},0,0};
    struct addr_struct dst = {0,{0},0,0};
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
        tob_op_write(buf, op);
    }
}

void guestLoadTaint(GReg guestSrc, LAddr localDst, int len, TaintOpBuffer *buf){
    struct addr_struct src = {0,{0},0,0};
    struct addr_struct dst = {0,{0},0,0};
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
        tob_op_write(buf, op);
    }
}

void guestDeleteTaint(GReg guestDst, int len, TaintOpBuffer *buf){
    struct addr_struct dst = {0,{0},0,0};
    TaintOp op;
    memset(&op, 0, sizeof(TaintOp));
    op.typ = DELETEOP;
    dst.typ = GREG;
    dst.val.gr = guestDst;
    int i;
    for (i = 0; i < len; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(buf, op);
    }
}

