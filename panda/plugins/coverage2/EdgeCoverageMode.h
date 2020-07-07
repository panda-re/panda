#ifndef COVERAGE2_EDGE_COVERAGEMODE_H
#define COVERAGE2_EDGE_COVERAGEMODE_H

#include <set>
#include <utility>

#include "CoverageMode.h"

namespace coverage2
{

using Edge = std::pair<std::pair<target_ulong, target_ulong>, std::pair<target_ulong, target_ulong>>;

class EdgeCoverageMode : public CoverageMode
{
public:
    EdgeCoverageMode();

    void process_block(CPUState *cpu, TranslationBlock *tb) override;

private:
    std::set<std::pair<target_ulong, target_ulong>> blocks;
    std::set<Edge> edges;

    std::pair<target_ulong, target_ulong> dummy_previous_block;
    std::pair<target_ulong, target_ulong> *previous_block_key_ptr;
};

}

#endif
