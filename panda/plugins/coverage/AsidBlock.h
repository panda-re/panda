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

template <> class hash<AsidBlock> {
public:
    using argument_type = AsidBlock;
    using result_type = size_t;
    result_type operator()(argument_type const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        result_type const h1 = std::hash<target_ulong>{}(s.asid);
        result_type const h2 = std::hash<target_ulong>{}(s.in_kernel);
        result_type const h3 = std::hash<Block>{}(s.block);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

}

static inline bool operator==(const AsidBlock& lhs, const AsidBlock& rhs)
{
    return (lhs.asid == rhs.asid) && (lhs.in_kernel == rhs.in_kernel) &&
        (lhs.block == rhs.block);
}

#endif
