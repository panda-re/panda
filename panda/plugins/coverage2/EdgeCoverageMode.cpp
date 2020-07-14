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
                     std::unordered_map<target_pid_t, Block *> *pprevs,
                     Block *cur)
{
    std::unique_ptr<OsiThread, void(*)(OsiThread*)> thread(
        get_current_thread(first_cpu), free_osithread);

    auto result = pprevs->insert({ thread->tid, &dummy });
    Block *prev = result.first->second;

    Edge e {
        .from = prev,
        .to = cur
    };
    edges->insert(e);
    pprevs->at(thread->tid) = cur;
}

EdgeCoverageMode::EdgeCoverageMode(const std::string& filename) :
    output_stream(filename)
{
    panda_require("osi");
    assert(init_osi_api());
}

void EdgeCoverageMode::process_block(CPUState *cpu, TranslationBlock *tb)
{
    Block block {
        .asid = panda_current_asid(cpu),
        .pc = tb->pc,
        .size = tb->size
    };
    auto result = blocks.insert(block);

    auto current_block_key_ptr = &(*std::get<0>(result));

    // Locate the first GUEST instruction in our TCG context.
    TCGOp *insert_point = find_first_guest_insn();
    assert(NULL != insert_point);

    // now lets insert our callback after the first instruction mark
    insert_call(&insert_point, &callback, &edges, &previous_blocks,
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
