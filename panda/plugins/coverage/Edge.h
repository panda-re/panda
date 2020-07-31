#ifndef COVERAGE_EDGE_H
#define COVERAGE_EDGE_H

#include <functional>

#include "Block.h"

/**
 * A structure representing edges.
 */
struct Edge
{
    Block from;
    Block to;
};

namespace std
{

template <> class hash<Edge> {
public:
    using argument_type = Edge;
    using result_type = size_t;
    result_type operator()(argument_type const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        result_type const h1 = std::hash<Block>{}(s.from);
        result_type const h2 = std::hash<Block>{}(s.to);
        return h1 ^ (h2 << 1);
    }
};

}

static inline bool operator==(const Edge& lhs,
                              const Edge& rhs)
{
    return (lhs.from == rhs.from) && (lhs.to == rhs.to);
}

#endif
