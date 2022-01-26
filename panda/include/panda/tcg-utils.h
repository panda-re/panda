#ifndef TCG_UTILS_H
#define TCG_UTILS_H

#include "panda/plugin.h"
#include "tcg.h"

#ifdef __cplusplus

#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

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
 * Template that converts uin64_t to a TCG constants. Not really inteded to be called directly.*/
template<typename A>
intptr_t insert_tcg_tmp(TCGOp **after_op, A value)
{
    auto tmp = tcg_temp_new_i64();
    *after_op = tcg_op_insert_after(&tcg_ctx, *after_op, INDEX_op_movi_i64, 2);
    TCGArg *store_args = &tcg_ctx.gen_opparam_buf[(*after_op)->args];
    store_args[0] = GET_TCGV_I64(tmp);
    store_args[1] = static_cast<TCGArg>(value);
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

    // Insert the call op. Here be dragons: the number of "arguments" passed to
    // the tcg_op_insert_after is NOT the number of call arguments. Instead,
    // the arguments in this context is the number of parameters to a call op.
    // A call op has N output parameters, M output parameters, a function
    // pointer, and a flags field. Therefore the number to pass to this
    // function then is N + M + 2. For this case, we have no output arguments,
    // so we take the number of input arguments and add 2 to compute how many
    // parameters this call op has.
    *after_op = tcg_op_insert_after(&tcg_ctx, *after_op, INDEX_op_call, ia.size() + 2);

    // Populate call op parameters.
    (*after_op)->callo = 0; // no return value
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
	std::string::size_type sz = 0;
	std::string::size_type full_len = value.length();
    auto max_value = std::numeric_limits<T>::max();
    auto tmp = std::stoull(value, &sz, 0);
    if (max_value < tmp) {
        std::stringstream ss;
        ss << "Value cannot be larger than " <<  max_value << ".";
        throw std::overflow_error(ss.str());
    } else if (sz < full_len) {
    	std::stringstream ss;
    	ss << "Invalid character(s) found in " << value << ".";
    	throw std::range_error(ss.str());
    }
    return static_cast<T>(tmp);
}

extern "C"
{
#endif
/**
 * Shared function to manage cpu exits.
 * 
 * Insert after any call that could trigger a generated cpu exit during.
 */
void check_cpu_exit(void*);

/**
 * Search the TCG context for the first guest instruction marker and return a
 * pointer to it.
 */
TCGOp *find_first_guest_insn(void);

/**
 * Search the TCG context for the guest instruction marker with the given
 * address.
 */
TCGOp *find_guest_insn_by_addr(target_ulong addr);


/* 
*  Search the TCG context for the last guest instruction marker and return
*  a pointer to it.
*/
TCGOp *find_last_guest_insn(void);

void insert_call_1p(TCGOp **after_op, void(*func)(void*), void *val);
void insert_call_2p(TCGOp **after_op, void(*func)(void*), void *val, void *val2);
void insert_call_3p(TCGOp **after_op, void(*func)(void*), void *val, void *val2, void* val3);
void insert_call_4p(TCGOp **after_op, void(*func)(void*), void *val, void *val2, void* val3, void* val4);

void call_1p_check_cpu_exit(void(*func)(void*), void* val);
void call_2p_check_cpu_exit(void(*func)(void*, void*), void* val, void* val2);
void call_3p_check_cpu_exit(void(*func)(void*, void*, void*), void* val, void* val2, void* val3);
void call_4p_check_cpu_exit(void(*func)(void*, void*, void*, void*), void* val, void* val2, void* val3, void* val4);
void call_5p_check_cpu_exit(void(*func)(void*, void*,void*, void*, void*), void* val, void* val2, void* val3, void* val4, void* val5);

#ifdef __cplusplus
}
#endif

#endif
