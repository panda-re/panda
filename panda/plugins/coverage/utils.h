#ifndef COVERAGE_UTILS_H
#define COVERAGE_UTILS_H

#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "panda/plugin.h"
#include "tcg.h"

/**
 * Search the TCG context for the first guest instruction marker and return a
 * pointer to it.
 */
TCGOp *find_first_guest_insn();

/**
 * Template that converts host pointers to TCG constants. Not really intended
 * to be called directly.
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
 * Base case for call argument insertion. Not really intended to be called
 * directly.
 */
template<typename Arg>
std::vector<intptr_t> insert_args(TCGOp **after_op, Arg arg)
{
    intptr_t tmp = insert_tcg_tmp(after_op, arg);
    return { tmp };
}

/**
 * Recursive case for call argument insertion. Not really intended to be called
 * directly.
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
 * limited to functions that return void and take at least one argument.
 *
 * Arguments: 
 *   after_op: The TCG op to insert after. After inserting the call, this value
 *             is updated so that subsequent calls to insert_call can be made.
 *
 *   func_ptr: A pointer to the function we want to call.
 *
 *   args ...: Variable length list of arguments to pass into the function at
 *             call time. Note that these arguments should not refer to
 *             something that will go out of scope (such as a stack variable).
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

    // The function and flag arguments come after the input and output args for
    // call TCG ops. So we are intentionally looking past the number of input
    // args (since there are no output args).
    
    // Set the function pointer for the call
    call_args[ia.size()] = reinterpret_cast<TCGArg>(func_ptr);

    // Set the call op flags. Note that TCG calls ops have flags that are used
    // by the optimizer. The argument array may have left over data, so we have
    // to explicitly zero the flags out. If we don't, some calls may get
    // optimized out leading to incorrect coverage data.
    call_args[ia.size() + 1] = 0;
}

/**
 * Helper function to parse a numeric value from a std::string. Throws an
 * exception if the value couldn't be parsed or doesn't fit into the
 * destination type.
 */
template<typename T>
T try_parse(const std::string& value)
{
    auto max_value = std::numeric_limits<T>::max();
    auto tmp = std::stoull(value, NULL, 0);
    if (max_value < tmp) {
        std::stringstream ss;
        ss << "Value cannot be larger than " <<  max_value << ".";
        throw std::overflow_error(ss.str());
    }
    return static_cast<T>(tmp);
}

#endif
