#ifndef __TAINT_UTILS_H_
#define __TAINT_UTILS_H_

#include <llvm/ADT/APInt.h>

static inline uint64_t apint_hi_bits(llvm::APInt value)
{
    return value.lshr(64).trunc(64).getZExtValue();
}

static inline uint64_t apint_lo_bits(llvm::APInt value)
{
    return value.trunc(64).getZExtValue();
}

static inline llvm::APInt make_128bit_apint(uint64_t hi, uint64_t lo)
{
    return (llvm::APInt(128, hi) << 64) | llvm::APInt(128, lo);
}

#endif
