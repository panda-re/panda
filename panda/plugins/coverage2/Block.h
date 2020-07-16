#ifndef COVERAGE2_BLOCK_H
#define COVERAGE2_BLOCK_H

#include <functional>

#include "panda/plugin.h"

struct Block
{
    target_ulong addr;
    target_ulong size;
};

namespace std
{

template <> class hash<Block> {
public:
    using argument_type = Block;
    using result_type = size_t;
    result_type operator()(argument_type const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        result_type const h1 = std::hash<target_ulong>{}(s.addr);
        result_type const h2 = std::hash<target_ulong>{}(s.size);
        return h1 ^ (h2 << 1);
    }
};

}

static inline bool operator==(const Block& lhs, const Block& rhs)
{
    return (lhs.addr == rhs.addr) && (lhs.size == rhs.size);
}

#endif
