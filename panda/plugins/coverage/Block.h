#ifndef COVERAGE_BLOCK_H
#define COVERAGE_BLOCK_H

#include <functional>

#include "panda/plugin.h"

/**
 * The common block structure, blocks are represented by address and size.
 */
struct Block
{
    target_ulong addr;
    target_ulong size;
};

// Below we have implemented std::hash for an '==' operator for use in
// unordered_set and map.
namespace std
{

template<>
class hash<Block> {
public:
    size_t operator()(Block const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        return s.addr ^ (s.size << 1);
    }
};

}

static inline bool operator==(const Block& lhs, const Block& rhs)
{
    return (lhs.addr == rhs.addr) && (lhs.size == rhs.size);
}

#endif
