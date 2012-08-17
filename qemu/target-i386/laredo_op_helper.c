/*
 * These are the x86 helpers that we want to be instrumented and analyzed with
 * LLVM.  This is temporary; ultimately, we should just process each
 * op_helper.c.  Let's give Fabrice or whoever is responsible for these awesome
 * macros a round of applause, and maybe think about entering this into the
 * obfuscated C contest.
 */
#include "cpu.h"
#include "dyngen-exec.h"
#include "helper.h"

#ifdef CONFIG_LLVM_INSTR_HELPERS

#ifdef CONFIG_LLVM
extern struct CPUX86State *env;
#endif

void printdynval(uintptr_t, int);
void dummy(void);

/*
 * Dummy function that uses printdynval() so it is included in the LLVM module
 * and we can use it for instrumentation.
 */
void dummy(){
    printdynval(0, 0);
}

/******************************************************************************/
/* MMX stuff */

#define SHIFT 0

#define FXOR(a, b) (a) ^ (b)
#define FCMPGTB(a, b) (int8_t)(a) > (int8_t)(b) ? -1 : 0
#define FAND(a, b) (a) & (b)
#define FADD(a, b) ((a) + (b))

#define Reg MMXReg
#define XMM_ONLY(...)
#define B(n) MMX_B(n)
#define W(n) MMX_W(n)
#define L(n) MMX_L(n)
#define Q(n) q
#define SUFFIX _mmx

#define SSE_HELPER_Q(name, F)\
void glue(name, SUFFIX) (Reg *d, Reg *s)\
{\
    d->Q(0) = F(d->Q(0), s->Q(0));\
    XMM_ONLY(\
    d->Q(1) = F(d->Q(1), s->Q(1));\
    )\
}

#define SSE_HELPER_B(name, F)\
void glue(name, SUFFIX) (Reg *d, Reg *s)\
{\
    d->B(0) = F(d->B(0), s->B(0));\
    d->B(1) = F(d->B(1), s->B(1));\
    d->B(2) = F(d->B(2), s->B(2));\
    d->B(3) = F(d->B(3), s->B(3));\
    d->B(4) = F(d->B(4), s->B(4));\
    d->B(5) = F(d->B(5), s->B(5));\
    d->B(6) = F(d->B(6), s->B(6));\
    d->B(7) = F(d->B(7), s->B(7));\
    XMM_ONLY(\
    d->B(8) = F(d->B(8), s->B(8));\
    d->B(9) = F(d->B(9), s->B(9));\
    d->B(10) = F(d->B(10), s->B(10));\
    d->B(11) = F(d->B(11), s->B(11));\
    d->B(12) = F(d->B(12), s->B(12));\
    d->B(13) = F(d->B(13), s->B(13));\
    d->B(14) = F(d->B(14), s->B(14));\
    d->B(15) = F(d->B(15), s->B(15));\
    )\
}

SSE_HELPER_Q(helper_pxor, FXOR)
SSE_HELPER_B(helper_pcmpgtb, FCMPGTB)
SSE_HELPER_Q(helper_pand, FAND)
SSE_HELPER_B(helper_paddb, FADD)

void glue(helper_pshufw, SUFFIX) (Reg *d, Reg *s, int order)
{
    Reg r;
    r.W(0) = s->W(order & 3);
    r.W(1) = s->W((order >> 2) & 3);
    r.W(2) = s->W((order >> 4) & 3);
    r.W(3) = s->W((order >> 6) & 3);
    *d = r;
}

void glue(helper_movl_mm_T0, SUFFIX) (Reg *d, uint32_t val)
{
    d->L(0) = val;
    d->L(1) = 0;
#if SHIFT == 1
    d->Q(1) = 0;
#endif
}

#define UNPCK_OP(base_name, base)                               \
                                                                \
void glue(helper_punpck ## base_name ## bw, SUFFIX) (Reg *d, Reg *s)   \
{                                                               \
    Reg r;                                              \
                                                                \
    r.B(0) = d->B((base << (SHIFT + 2)) + 0);                   \
    r.B(1) = s->B((base << (SHIFT + 2)) + 0);                   \
    r.B(2) = d->B((base << (SHIFT + 2)) + 1);                   \
    r.B(3) = s->B((base << (SHIFT + 2)) + 1);                   \
    r.B(4) = d->B((base << (SHIFT + 2)) + 2);                   \
    r.B(5) = s->B((base << (SHIFT + 2)) + 2);                   \
    r.B(6) = d->B((base << (SHIFT + 2)) + 3);                   \
    r.B(7) = s->B((base << (SHIFT + 2)) + 3);                   \
XMM_ONLY(                                                       \
    r.B(8) = d->B((base << (SHIFT + 2)) + 4);                   \
    r.B(9) = s->B((base << (SHIFT + 2)) + 4);                   \
    r.B(10) = d->B((base << (SHIFT + 2)) + 5);                  \
    r.B(11) = s->B((base << (SHIFT + 2)) + 5);                  \
    r.B(12) = d->B((base << (SHIFT + 2)) + 6);                  \
    r.B(13) = s->B((base << (SHIFT + 2)) + 6);                  \
    r.B(14) = d->B((base << (SHIFT + 2)) + 7);                  \
    r.B(15) = s->B((base << (SHIFT + 2)) + 7);                  \
)                                                               \
    *d = r;                                                     \
}                                                               \
                                                                \
void glue(helper_punpck ## base_name ## wd, SUFFIX) (Reg *d, Reg *s)   \
{                                                               \
    Reg r;                                              \
                                                                \
    r.W(0) = d->W((base << (SHIFT + 1)) + 0);                   \
    r.W(1) = s->W((base << (SHIFT + 1)) + 0);                   \
    r.W(2) = d->W((base << (SHIFT + 1)) + 1);                   \
    r.W(3) = s->W((base << (SHIFT + 1)) + 1);                   \
XMM_ONLY(                                                       \
    r.W(4) = d->W((base << (SHIFT + 1)) + 2);                   \
    r.W(5) = s->W((base << (SHIFT + 1)) + 2);                   \
    r.W(6) = d->W((base << (SHIFT + 1)) + 3);                   \
    r.W(7) = s->W((base << (SHIFT + 1)) + 3);                   \
)                                                               \
    *d = r;                                                     \
}                                                               \
                                                                \
void glue(helper_punpck ## base_name ## dq, SUFFIX) (Reg *d, Reg *s)   \
{                                                               \
    Reg r;                                              \
                                                                \
    r.L(0) = d->L((base << SHIFT) + 0);                         \
    r.L(1) = s->L((base << SHIFT) + 0);                         \
XMM_ONLY(                                                       \
    r.L(2) = d->L((base << SHIFT) + 1);                         \
    r.L(3) = s->L((base << SHIFT) + 1);                         \
)                                                               \
    *d = r;                                                     \
}                                                               \
                                                                \
XMM_ONLY(                                                       \
void glue(helper_punpck ## base_name ## qdq, SUFFIX) (Reg *d, Reg *s)  \
{                                                               \
    Reg r;                                              \
                                                                \
    r.Q(0) = d->Q(base);                                        \
    r.Q(1) = s->Q(base);                                        \
    *d = r;                                                     \
}                                                               \
)

UNPCK_OP(l, 0)

void glue(helper_psrld, SUFFIX)(Reg *d, Reg *s)
{
    int shift;

    if (s->Q(0) > 31) {
        d->Q(0) = 0;
#if SHIFT == 1
        d->Q(1) = 0;
#endif
    } else {
        shift = s->B(0);
        d->L(0) >>= shift;
        d->L(1) >>= shift;
#if SHIFT == 1
        d->L(2) >>= shift;
        d->L(3) >>= shift;
#endif
    }
}

void glue(helper_pslld, SUFFIX)(Reg *d, Reg *s)
{
    int shift;

    if (s->Q(0) > 31) {
        d->Q(0) = 0;
#if SHIFT == 1
        d->Q(1) = 0;
#endif
    } else {
        shift = s->B(0);
        d->L(0) <<= shift;
        d->L(1) <<= shift;
#if SHIFT == 1
        d->L(2) <<= shift;
        d->L(3) <<= shift;
#endif
    }
}


/******************************************************************************/
/* XMM stuff */
/* Note: currently assuming these are not called */


#undef SHIFT
#undef Reg
#undef XMM_ONLY
#undef B
#undef W
#undef L
#undef Q
#undef SUFFIX

#define SHIFT 1
#define Reg XMMReg
#define XMM_ONLY(...) __VA_ARGS__
#define B(n) XMM_B(n)
#define W(n) XMM_W(n)
#define L(n) XMM_L(n)
#define Q(n) XMM_Q(n)
#define SUFFIX _xmm

#define SSE_HELPER_Q(name, F)\
void glue(name, SUFFIX) (Reg *d, Reg *s)\
{\
    d->Q(0) = F(d->Q(0), s->Q(0));\
    XMM_ONLY(\
    d->Q(1) = F(d->Q(1), s->Q(1));\
    )\
}

#define SSE_HELPER_B(name, F)\
void glue(name, SUFFIX) (Reg *d, Reg *s)\
{\
    d->B(0) = F(d->B(0), s->B(0));\
    d->B(1) = F(d->B(1), s->B(1));\
    d->B(2) = F(d->B(2), s->B(2));\
    d->B(3) = F(d->B(3), s->B(3));\
    d->B(4) = F(d->B(4), s->B(4));\
    d->B(5) = F(d->B(5), s->B(5));\
    d->B(6) = F(d->B(6), s->B(6));\
    d->B(7) = F(d->B(7), s->B(7));\
    XMM_ONLY(\
    d->B(8) = F(d->B(8), s->B(8));\
    d->B(9) = F(d->B(9), s->B(9));\
    d->B(10) = F(d->B(10), s->B(10));\
    d->B(11) = F(d->B(11), s->B(11));\
    d->B(12) = F(d->B(12), s->B(12));\
    d->B(13) = F(d->B(13), s->B(13));\
    d->B(14) = F(d->B(14), s->B(14));\
    d->B(15) = F(d->B(15), s->B(15));\
    )\
}

SSE_HELPER_Q(helper_pxor, FXOR)
SSE_HELPER_B(helper_pcmpgtb, FCMPGTB)
SSE_HELPER_Q(helper_pand, FAND)
SSE_HELPER_B(helper_paddb, FADD)

void glue(helper_movl_mm_T0, SUFFIX) (Reg *d, uint32_t val)
{
    d->L(0) = val;
    d->L(1) = 0;
#if SHIFT == 1
    d->Q(1) = 0;
#endif
}

UNPCK_OP(l, 0)

void glue(helper_psrld, SUFFIX)(Reg *d, Reg *s)
{
    int shift;

    if (s->Q(0) > 31) {
        d->Q(0) = 0;
#if SHIFT == 1
        d->Q(1) = 0;
#endif
    } else {
        shift = s->B(0);
        d->L(0) >>= shift;
        d->L(1) >>= shift;
#if SHIFT == 1
        d->L(2) >>= shift;
        d->L(3) >>= shift;
#endif
    }
}

void glue(helper_pslld, SUFFIX)(Reg *d, Reg *s)
{
    int shift;

    if (s->Q(0) > 31) {
        d->Q(0) = 0;
#if SHIFT == 1
        d->Q(1) = 0;
#endif
    } else {
        shift = s->B(0);
        d->L(0) <<= shift;
        d->L(1) <<= shift;
#if SHIFT == 1
        d->L(2) <<= shift;
        d->L(3) <<= shift;
#endif
    }
}

#endif

