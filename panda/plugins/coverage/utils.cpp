#include "utils.h"

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
