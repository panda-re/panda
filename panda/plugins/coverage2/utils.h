#ifndef COVERAGE2_UTILS_H
#define COVERAGE2_UTILS_H

#include <vector>

#include "panda/plugin.h"
#include "tcg.h"

/**
 * Search the TCG context for the first guest instruction marker and return a
 * pointer to it.
 */
TCGOp *find_first_guest_insn();

/**
 * Template that converts host pointers to TCG constants.
 */
template<typename A>
intptr_t insert_tcg_tmp(TCGOp **after_op, A *value)
{
    auto tmp = tcg_temp_new_i64();
    *after_op = tcg_op_insert_after(&tcg_ctx, *after_op, INDEX_op_movi_i64, 2);
    TCGArg *store_args = &tcg_ctx.gen_opparam_buf[(*after_op)->args];
    store_args[0] = GET_TCGV_I64(tmp);
    store_args[1] = reinterpret_cast<TCGArg>(value);
    return GET_TCGV_I64(tmp);
}

/**
 * Base case for call argument insertion.
 */
template<typename Arg>
std::vector<intptr_t> insert_args(TCGOp **after_op, Arg arg)
{
    intptr_t tmp = insert_tcg_tmp(after_op, arg);
    return { tmp };
}

/**
 * Recursive case for call argument insertion.
 */
template<typename First, typename... Args>
std::vector<intptr_t> insert_args(TCGOp **after_op, First arg, Args... args)
{
    auto v1 = insert_args(after_op, arg);
    auto v2 = insert_args(after_op, args ...);
    std::vector<intptr_t> result(v1);
    result.insert(result.end(), v2.begin(), v2.end());
    return result;
}

/**
 * A template function that inserts a call into the TCG context. Currently
 * limited to functions that return void.
 */
template<typename F, typename... A>
void insert_call(TCGOp **after_op, F *func_ptr, A... args)
{
    // Insert all arguments as TCG temporaries.
    std::vector<intptr_t> ia = insert_args(after_op, args ...);

    // Insert the call op.
    *after_op = tcg_op_insert_after(&tcg_ctx, *after_op, INDEX_op_call, ia.size() + 1);

    // Populate call op parameters.
    (*after_op)->calli = ia.size();
    TCGArg *call_args = &tcg_ctx.gen_opparam_buf[(*after_op)->args];
    for (int i = 0; i < ia.size(); i++) {
        call_args[i] = ia.at(i);
    }
    call_args[ia.size()] = reinterpret_cast<TCGArg>(func_ptr);
}


#endif
