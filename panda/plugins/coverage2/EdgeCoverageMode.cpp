#include <memory>

#include "EdgeCoverageMode.h"
#include "utils.h"

#include "tcg.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

namespace coverage2
{

static Block dummy;

static void callback(std::unordered_set<Edge> *edges,
                     Block **prev,
                     Block *cur)
{
    Edge e {
        .from = *prev,
        .to = cur
    };
    edges->insert(e);
    *prev = cur;
}

EdgeCoverageMode::EdgeCoverageMode(const std::string& filename) :
    output_stream(filename), prev(&dummy)
{
}

void EdgeCoverageMode::process_block(CPUState *cpu, TranslationBlock *tb)
{
    Block block {
        .pc = tb->pc,
        .size = tb->size
    };
    auto result = blocks.insert(block);

    auto current_block_key_ptr = &(*std::get<0>(result));

    // Locate the first GUEST instruction in our TCG context.
    TCGOp *insert_point = find_first_guest_insn();
    assert(NULL != insert_point);

    // now lets insert our callback after the first instruction mark
    insert_call(&insert_point, &callback, &edges, &prev,
                current_block_key_ptr);
}

void EdgeCoverageMode::process_results()
{
    output_stream << "from pc,from size,to pc,to size\n";
    for (Edge edge : edges) {
        if (&dummy == edge.from) {
            // skip edges with the dummy block, not a real edge!
            continue;
        }

        output_stream << "0x" << std::hex << edge.from->pc   << ","
                      << std::dec << edge.from->size << ","
                      << "0x" << std::hex << edge.to->pc     << ","
                      << std::dec << edge.to->size   << "\n";
    }
}

}
