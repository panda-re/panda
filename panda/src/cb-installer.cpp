#include "panda/tcg-utils.h"

extern "C"{
    #include "panda/callbacks/cb-support.h"
}


void panda_install_block_callbacks(CPUState* cpu, TranslationBlock *tb){
    TCGOp* start = find_first_guest_insn();
    if (start != NULL){
        insert_call(&start, panda_callbacks_start_block_exec, first_cpu, tb);
    }else{
        printf("error on start\n");
    }
    
    bool found_exit = false;
    TCGOp *last_op = NULL;
    TCGOp *op = NULL;
    for (int oi = tcg_ctx.gen_op_buf[0].next; oi != 0; oi = op->next) {
        op = &tcg_ctx.gen_op_buf[oi];
        if (INDEX_op_exit_tb == op->opc) {
            insert_call(&last_op, panda_callbacks_end_block_exec, first_cpu, tb);
            found_exit = true;
        }
        last_op = op;
    }
    if (!found_exit) {
        printf("error on end %d\n", tb->size);
    }
}
