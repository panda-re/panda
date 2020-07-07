#include "EdgeCoverageMode.h"

#include "tcg.h"

namespace coverage2
{

static void callback(std::set<Edge> *edges,
                     std::pair<target_ulong, target_ulong> *cur,
                     std::pair<target_ulong, target_ulong> **pprev)
{
    Edge e(*cur, **pprev);
    edges->insert(e);
    *pprev = cur;
}

EdgeCoverageMode::EdgeCoverageMode() :
    dummy_previous_block(0, 0), previous_block_key_ptr(&dummy_previous_block)
{
}

void EdgeCoverageMode::process_block(CPUState *cpu, TranslationBlock *tb)
{
    auto key = std::make_pair(panda_current_asid(cpu), tb->pc);
    auto result = blocks.insert(key);

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
    auto prev_key_pptr_tmp = tcg_temp_new_i64();
    TCGOp *prev_key_pptr_store_op = tcg_op_insert_after(&tcg_ctx, block_key_ptr_store_op, INDEX_op_movi_i64, 2);
    TCGArg *prev_key_pptr_store_args = &tcg_ctx.gen_opparam_buf[prev_key_pptr_store_op->args];
    prev_key_pptr_store_args[0] = GET_TCGV_I64(prev_key_pptr_tmp);
    prev_key_pptr_store_args[1] = reinterpret_cast<TCGArg>(&previous_block_key_ptr);

    // Now the temporary holding the edge set pointer.
    auto edge_set_ptr_tmp = tcg_temp_new_i64();
    TCGOp *edge_set_ptr_store_op = tcg_op_insert_after(&tcg_ctx, prev_key_pptr_store_op, INDEX_op_movi_i64, 2);
    TCGArg *edge_set_ptr_store_args = &tcg_ctx.gen_opparam_buf[edge_set_ptr_store_op->args];
    edge_set_ptr_store_args[0] = GET_TCGV_I64(edge_set_ptr_tmp);
    edge_set_ptr_store_args[1] = reinterpret_cast<TCGArg>(&edges);

    // Insert the callback.
    TCGOp *call_op = tcg_op_insert_after(&tcg_ctx, edge_set_ptr_store_op, INDEX_op_call, 4);
    call_op->calli = 3;
    TCGArg *call_args = &tcg_ctx.gen_opparam_buf[call_op->args];
    call_args[3] = reinterpret_cast<TCGArg>(&callback);
    call_args[2] = GET_TCGV_I64(prev_key_pptr_tmp);
    call_args[1] = GET_TCGV_I64(block_key_ptr_tmp);
    call_args[0] = GET_TCGV_I64(edge_set_ptr_tmp);

    //fprintf(stderr, "Current TCG context:\n");
    //fprintf(stderr, "ptr = %p\n", current_block_key_ptr);
    //tcg_dump_ops(&tcg_ctx);


/*    auto tb_tmp = tcg_temp_new_i64();
    TCGOp *tb_store_op = tcg_op_insert_after(&tcg_ctx, last_guest_insn_mark, INDEX_op_movi_i64, 2);
    TCGArg *tb_store_args = &tcg_ctx.gen_opparam_buf[tb_store_op->args];
    tb_store_args[0] = GET_TCGV_I64(tb_tmp);
    tb_store_args[1] = reinterpret_cast<TCGArg>(tb);

    auto cpu_tmp = tcg_temp_new_i64();
    TCGOp *cpu_store_op = tcg_op_insert_after(&tcg_ctx, tb_store_op, INDEX_op_movi_i64, 2);
    TCGArg *cpu_store_args = &tcg_ctx.gen_opparam_buf[cpu_store_op->args];
    cpu_store_args[0] = GET_TCGV_I64(cpu_tmp);
    cpu_store_args[1] = reinterpret_cast<TCGArg>(cpu);

    TCGOp *call_op = tcg_op_insert_after(&tcg_ctx, cpu_store_op, INDEX_op_call, 3);
    call_op->calli = 2;
    TCGArg *call_args = &tcg_ctx.gen_opparam_buf[call_op->args];
    call_args[2] = reinterpret_cast<TCGArg>(&my_func);
    call_args[1] = GET_TCGV_I64(tb_tmp);
    call_args[0] = GET_TCGV_I64(cpu_tmp); */
}

}
