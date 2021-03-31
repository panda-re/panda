#ifndef COVERAGE_OSI_BLOCK_H
#define COVERAGE_OSI_BLOCK_H

#include <functional>
#include <string>

#include "panda/plugin.h"
#include "osi/osi_types.h"

#include "Block.h"

/**
 * A struct type that adds OSI information to a block.
 */
struct OsiBlock
{
    target_pid_t pid;
    target_pid_t tid;
    target_ulong in_kernel;
    std::string process_name;
    Block block;
};

namespace std
{

template<>
class hash<OsiBlock> {
public:
    size_t operator()(OsiBlock const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        size_t const bh = std::hash<Block>{}(s.block);
        return s.pid ^ (s.tid << 1) ^ (bh << 2);
    }
};

}

static inline bool operator==(const OsiBlock& lhs, const OsiBlock& rhs)
{
    return (lhs.pid == rhs.pid) && (lhs.tid == rhs.tid) &&
           (lhs.block == rhs.block);
}

#endif
