#include <memory>

#include "EdgeCoverageMode.h"

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
    std::unique_ptr<OsiThread, void(*)(OsiThread*)> thread(get_current_thread(first_cpu), free_osithread);

    auto result = pprevs->insert({ thread->tid, &dummy });
    Block *prev = result.first->second;

    Edge e {
        .from = cur,
        .to = prev
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

    //printf("current block ptr = %p\n", current_block_key_ptr);

    // Locate the first GUEST instruction in our TCG context.
    TCGOp *op = NULL, *first_guest_insn_mark = NULL;
    for (int oi = tcg_ctx.gen_op_buf[0].next; oi != 0; oi = op->next) {
        op = &tcg_ctx.gen_op_buf[oi];
        if (INDEX_op_insn_start == op->opc) {
            first_guest_insn_mark = op;
            break;
        }
    }
    assert(NULL != first_guest_insn_mark);

    // now lets insert a call after the mark

    // Let's create a temporary that holds the pointer to our the block's key.
    auto block_key_ptr_tmp = tcg_temp_new_i64();
    TCGOp *block_key_ptr_store_op = tcg_op_insert_after(&tcg_ctx, first_guest_insn_mark, INDEX_op_movi_i64, 2);
    TCGArg *block_key_ptr_store_args = &tcg_ctx.gen_opparam_buf[block_key_ptr_store_op->args];
    block_key_ptr_store_args[0] = GET_TCGV_I64(block_key_ptr_tmp);
    block_key_ptr_store_args[1] = reinterpret_cast<TCGArg>(current_block_key_ptr);

    // Now the temporary holding the previous block key pointer.
    auto prev_blocks_tmp = tcg_temp_new_i64();
    TCGOp *prev_blocks_store_op = tcg_op_insert_after(&tcg_ctx, block_key_ptr_store_op, INDEX_op_movi_i64, 2);
    TCGArg *prev_blocks_store_args = &tcg_ctx.gen_opparam_buf[prev_blocks_store_op->args];
    prev_blocks_store_args[0] = GET_TCGV_I64(prev_blocks_tmp);
    prev_blocks_store_args[1] = reinterpret_cast<TCGArg>(&previous_blocks);

    // Now the temporary holding the edge set pointer.
    auto edge_set_ptr_tmp = tcg_temp_new_i64();
    TCGOp *edge_set_ptr_store_op = tcg_op_insert_after(&tcg_ctx, prev_blocks_store_op, INDEX_op_movi_i64, 2);
    TCGArg *edge_set_ptr_store_args = &tcg_ctx.gen_opparam_buf[edge_set_ptr_store_op->args];
    edge_set_ptr_store_args[0] = GET_TCGV_I64(edge_set_ptr_tmp);
    edge_set_ptr_store_args[1] = reinterpret_cast<TCGArg>(&edges);

    // Insert the callback.
    TCGOp *call_op = tcg_op_insert_after(&tcg_ctx, edge_set_ptr_store_op, INDEX_op_call, 4);
    call_op->calli = 3;
    TCGArg *call_args = &tcg_ctx.gen_opparam_buf[call_op->args];
    call_args[3] = reinterpret_cast<TCGArg>(&callback);
    call_args[2] = GET_TCGV_I64(block_key_ptr_tmp);
    call_args[1] = GET_TCGV_I64(prev_blocks_tmp);
    call_args[0] = GET_TCGV_I64(edge_set_ptr_tmp);
}

void EdgeCoverageMode::process_results()
{
    output_stream << "from pc,from size,to pc,to size\n";
    for (Edge edge : edges) {
        output_stream << std::hex << edge.from->pc   << ","
                      << std::dec << edge.from->size << ","
                      << std::hex << edge.to->pc     << ","
                      << std::dec << edge.to->size   << "\n";
    }
}

}
