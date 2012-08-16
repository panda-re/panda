/*
 * These are the ARM helpers that we want to be instrumented and analyzed with
 * LLVM.  This is temporary; ultimately, we should just process each
 * op_helper.c.
 */
#include "cpu.h"
#include "dyngen-exec.h"
#include "helper.h"

#ifdef CONFIG_LLVM_INSTR_HELPERS

#define SIGNBIT (uint32_t)0x80000000
#define SIGNBIT64 ((uint64_t)1 << 63)

#ifdef CONFIG_LLVM
extern struct CPUARMState *env;
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

/* ??? Flag setting arithmetic is awkward because we need to do comparisons.
   The only way to do that in TCG is a conditional branch, which clobbers
   all our temporaries.  For now implement these as helper functions.  */

uint32_t HELPER (add_cc)(uint32_t a, uint32_t b)
{
    uint32_t result;
    result = a + b;
    //printf("%d\n", env->NF); //rw test
    env->NF = env->ZF = result;
    env->CF = result < a;
    env->VF = (a ^ b ^ -1) & (a ^ result);
    return result;
}

uint32_t HELPER(sub_cc)(uint32_t a, uint32_t b)
{
    uint32_t result;
    result = a - b;
    env->NF = env->ZF = result;
    env->CF = a >= b;
    env->VF = (a ^ b) & (a ^ result);
    return result;
}

/* Similarly for variable shift instructions.  */

uint32_t HELPER(shl)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return x << shift;
}

uint32_t HELPER(shr)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return (uint32_t)x >> shift;
}

#endif // CONFIG_LLVM_INSTR_HELPERS

