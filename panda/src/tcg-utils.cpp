#include "panda/tcg-utils.h"

extern "C"
{

TCGOp *find_first_guest_insn()
{
    TCGOp *op = NULL;
    TCGOp *first_guest_insn_mark = NULL; 
    for (int oi = tcg_ctx.gen_op_buf[0].next; oi != 0; oi = op->next) {
        op = &tcg_ctx.gen_op_buf[oi];
        if (INDEX_op_insn_start == op->opc) {
            first_guest_insn_mark = op;
            break;
        }
    }
    return first_guest_insn_mark;
}

// return the op right before exit
TCGOp *find_last_guest_insn()
{
    TCGOp *last_op = NULL;
    TCGOp *op = NULL;
    TCGOp *last_guest_insn_mark = NULL; 
    for (int oi = tcg_ctx.gen_op_buf[0].next; oi != 0; oi = op->next) {
        op = &tcg_ctx.gen_op_buf[oi];
        if (INDEX_op_exit_tb == op->opc) {
            last_guest_insn_mark = last_op;
            break;
        }
        last_op = op;
    }
    return last_guest_insn_mark;
}

TCGOp *find_guest_insn_by_addr(target_ulong addr)
{
    TCGOp *op = NULL;
    TCGOp *guest_insn_mark = NULL; 
    for (int oi = tcg_ctx.gen_op_buf[0].next; oi != 0; oi = op->next) {
        op = &tcg_ctx.gen_op_buf[oi];
        if (INDEX_op_insn_start == op->opc) {
            TCGArg *args = &tcg_ctx.gen_opparam_buf[op->args];
            target_ulong a;
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
            a = static_cast<target_ulong>(args[1] << 32);
            a |= args[0];
#else
            a = args[0];
#endif
            if (addr == a) {
                guest_insn_mark = op;
                break;
            }
        }
    }
    return guest_insn_mark;
}

void insert_call_1p(TCGOp **after_op, void(*func)(void*), void *val)
{
    insert_call(after_op, func, val);
}

}
