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
    TCGOp* end = find_last_guest_insn();
    if (end != NULL){
        insert_call(&end, panda_callbacks_end_block_exec, first_cpu, tb);
    }else{
        printf("error on end %d\n", tb->size);
    }
}