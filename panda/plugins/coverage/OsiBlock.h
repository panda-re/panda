#ifndef COVERAGE2_OSI_BLOCK_H
#define COVERAGE2_OSI_BLOCK_H

#include <functional>
#include <string>

#include "panda/plugin.h"
#include "osi/osi_types.h"

#include "Block.h"

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

template <> class hash<OsiBlock> {
public:
    using argument_type = OsiBlock;
    using result_type = size_t;
    result_type operator()(argument_type const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        result_type const h1 = std::hash<target_pid_t>{}(s.pid);
        result_type const h2 = std::hash<target_pid_t>{}(s.tid);
        result_type const h3 = std::hash<Block>{}(s.block);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

}

static inline bool operator==(const OsiBlock& lhs, const OsiBlock& rhs)
{
    return (lhs.pid == rhs.pid) && (lhs.tid == rhs.tid) &&
           (lhs.block == rhs.block);
}

#endif
