#ifndef COVERAGE_ASID_BLOCK_H
#define COVERAGE_ASID_BLOCK_H

#include <functional>

#include "panda/plugin.h"

#include "Block.h"

/**
 * A structure that stores the ASID along with a block.
 */
struct AsidBlock
{
    target_ulong asid;
    target_ulong in_kernel;
    Block block;
};

namespace std
{

template<>
class hash<AsidBlock> {
public:
    size_t operator()(AsidBlock const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        size_t const bh = std::hash<Block>{}(s.block);
        return s.asid ^ (s.in_kernel << 1) ^ (bh << 2);
    }
};

}

static inline bool operator==(const AsidBlock& lhs, const AsidBlock& rhs)
{
    return (lhs.asid == rhs.asid) && (lhs.in_kernel == rhs.in_kernel) &&
        (lhs.block == rhs.block);
}

#endif
