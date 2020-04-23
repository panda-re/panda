#ifndef __TAINT_UTILS_H_
#define __TAINT_UTILS_H_

#include "qemu/host-utils.h"

/**
 * Count leading zeroes for unsigned 128-bit integers.
 */
static inline int clz128(unsigned __int128 val)
{
    uint64_t hi = static_cast<uint64_t>(val >> 64);
    uint64_t lo = static_cast<uint64_t>(val);
    return 0 != hi ? clz64(hi) : clz64(hi) + clz64(lo);
}

/**
 * Count trailing zeroes for unsigned 128-bit integers.
 */
static inline int ctz128(unsigned __int128 val)
{
    uint64_t hi = static_cast<uint64_t>(val >> 64);
    uint64_t lo = static_cast<uint64_t>(val);
    return 0 != lo ? ctz64(lo) : ctz64(hi) + ctz64(lo);
}

#endif
