#include "panda/tcg-utils.h"

TCGOp *find_guest_insn(int index)
{
    TCGOp *op = NULL;
    TCGOp *guest_insn_mark = NULL; 
    int ci = 0;
    for (int oi = tcg_ctx.gen_op_buf[0].next; oi != 0; oi = op->next) {
        op = &tcg_ctx.gen_op_buf[oi];
        if (INDEX_op_insn_start == op->opc) {
            if (index == ci) {
                guest_insn_mark = op;
                break;
            }
            ci++;
        }
    }
    return guest_insn_mark;
}
