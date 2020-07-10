#ifndef COVERAGE2_EDGE_COVERAGEMODE_H
#define COVERAGE2_EDGE_COVERAGEMODE_H

#include <fstream>
#include <functional>
#include <unordered_set>
#include <unordered_map>
#include <utility>

#include "CoverageMode.h"

struct Block
{
    target_ulong asid;
    target_ulong pc;
    target_ulong size;
};

namespace std
{
template <> class hash<Block>
{
public:
    size_t operator()(Block const &blk) const noexcept
    {
        size_t const h1 = std::hash<target_ulong>{}(blk.asid);
        size_t const h2 = std::hash<target_ulong>{}(blk.pc);
        size_t const h3 = std::hash<target_ulong>{}(blk.size);
        return h1 ^ (h2 << 2) ^ (h3 << 2);
    }
};
}

static inline bool operator==(const Block &lhs, const Block &rhs)
{
    return (lhs.asid == rhs.asid) && (lhs.pc == rhs.pc) && (lhs.size == rhs.size);
}

struct Edge
{
    Block *from;
    Block *to;
};

namespace std
{
template <> class hash<Edge>
{
public:
    size_t operator()(Edge const &edge) const noexcept
    {
        size_t const h1 = std::hash<Block>{}(*edge.from);
        size_t const h2 = std::hash<Block>{}(*edge.to);
        return h1 ^ (h2 << 2);
    }
};
}

static inline bool operator==(const Edge &lhs, const Edge &rhs)
{
    return ((*lhs.from) == (*rhs.from)) && ((*lhs.to) == (*rhs.to));
}

namespace coverage2
{

class EdgeCoverageMode : public CoverageMode
{
public:
    EdgeCoverageMode(const std::string &filename);

    void process_block(CPUState *cpu, TranslationBlock *tb) override;

    void process_results() override;

private:
    std::unordered_set<Block> blocks;
    std::unordered_set<Edge> edges;

    std::unordered_map<target_pid_t, Block *> previous_blocks;

    std::ofstream output_stream;
};

}

#endif
