#include "panda/tcg-utils.h"
#include <vector>
#include <algorithm>

extern "C"
{

bool qemu_in_vcpu_thread(void);

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
                // NOTE: consider adding something to adjust for panda_precise_pc
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

void insert_call_2p(TCGOp **after_op, void(*func)(void*), void *val, void* val2)
{
    insert_call(after_op, func, val, val2);
}

void insert_call_3p(TCGOp **after_op, void(*func)(void*), void *val, void* val2, void* val3)
{
    insert_call(after_op, func, val, val2, val3);
}

void insert_call_4p(TCGOp **after_op, void(*func)(void*), void *val, void* val2, void* val3, void* val4)
{
    insert_call(after_op, func, val, val2, val3, val4);
}

void check_cpu_exit(void* val){
    if (panda_exit_cpu() && qemu_in_vcpu_thread() && first_cpu->running){
        cpu_loop_exit_noexc(first_cpu);
    }
}

struct previous_call {
    bool valid;
    int n;
    uint64_t func;
    uint64_t cpu;
    uint64_t tb;
    uint64_t a;
    uint64_t b;
    uint64_t c;
};

struct previous_call last_call = {
    .valid = false,
    .n = 0,
    .func = 0,
    .cpu = 0,
    .tb = 0,
    .a = 0,
    .b = 0,
    .c = 0,
};


/**
 * Triggering mechanism for CPU exit after retirement of call.
 * 
 * This function can actually run twice on each block.
 * 
 * NOTE: resist the urge to template (Rust FFI) or macro.
 * I tried to macro it. It's far more confusing than the this is.
 */ 
void call_1p_check_cpu_exit(void(*func)(void*), void* val){
    if (last_call.valid){
        if (last_call.n == 1 && last_call.func == (uint64_t)func && last_call.cpu == (uint64_t)val){
            last_call.valid = false;
        }
    }else{
        func(val);
        if (panda_exit_cpu() && qemu_in_vcpu_thread() && first_cpu->running){
            printf("exit loop inserting %lx\n", (long unsigned int)(void*)func);
            last_call.valid = true;
            last_call.n = (uint64_t)1;
            last_call.func = (uint64_t)func;
            last_call.cpu = (uint64_t)val;
            cpu_loop_exit_noexc(first_cpu);
        }
    }
}

void call_2p_check_cpu_exit(void(*func)(void*,void*), void* val, void* val2){
    if (last_call.valid){
        if (last_call.n == 2 && last_call.func == (uint64_t)func && last_call.cpu == (uint64_t)val){
            TranslationBlock *tb = (TranslationBlock *)last_call.tb;
            TranslationBlock *tb2 = (TranslationBlock *)val2;
            if (last_call.tb == (uint64_t)val2 || (tb2 != NULL && tb != NULL && tb->pc == tb2->pc)){
                last_call.valid = false;
            }
        }
    }else{
        func(val, val2);
        if (panda_exit_cpu() && qemu_in_vcpu_thread() && first_cpu->running){
            printf("exit loop inserting %lx\n", (long unsigned int)(void*)func);
            last_call.valid = true;
            last_call.n = (uint64_t)2;
            last_call.func = (uint64_t)func;
            last_call.cpu = (uint64_t)val;
            last_call.tb = (uint64_t)val2;
            cpu_loop_exit_noexc(first_cpu);
        }
    }
}

void call_3p_check_cpu_exit(void(*func)(void*,void*,void*), void* val, void* val2, void* val3){
    if (last_call.valid){
        if (last_call.n == 3 && last_call.func == (uint64_t)func && last_call.cpu == (uint64_t)val && last_call.a == (uint64_t)val3){
            TranslationBlock *tb = (TranslationBlock *)last_call.tb;
            TranslationBlock *tb2 = (TranslationBlock *)val2;
            if (last_call.tb == (uint64_t)val2 || (tb2 != NULL && tb != NULL && tb->pc == tb2->pc)){
                printf("found func %p\n", val3);
                last_call.valid = false;
            }
        }
    }else{
        func(val, val2, val3);
        if (panda_exit_cpu() && qemu_in_vcpu_thread() && first_cpu->running){
            printf("exit loop inserting %lx\n", (long unsigned int)(void*)func);
            last_call.valid = true;
            last_call.n = (uint64_t)3;
            last_call.func = (uint64_t)func;
            last_call.cpu = (uint64_t)val;
            last_call.tb = (uint64_t)val2;
            last_call.a = (uint64_t)val3;
            cpu_loop_exit_noexc(first_cpu);
        }
    }
}

void call_4p_check_cpu_exit(void(*func)(void*,void*,void*,void*), void* val, void* val2, void* val3, void* val4){
    if (last_call.valid){
        if (last_call.n == 4 && last_call.func == (uint64_t)func && last_call.cpu == (uint64_t)val && last_call.a == (uint64_t)val3 && last_call.b == (uint64_t)val4){
            TranslationBlock *tb = (TranslationBlock *)last_call.tb;
            TranslationBlock *tb2 = (TranslationBlock *)val2;
            if (last_call.tb == (uint64_t)val2 || (tb2 != NULL && tb != NULL && tb->pc == tb2->pc)){
                last_call.valid = false;
            }
        }
    }else{
        func(val, val2, val3, val4);
        if (panda_exit_cpu() && qemu_in_vcpu_thread() && first_cpu->running){
            printf("exit loop inserting %lx\n", (long unsigned int)(void*)func);
            last_call.valid = true;
            last_call.n = (uint64_t)4;
            last_call.func = (uint64_t)func;
            last_call.cpu = (uint64_t)val;
            last_call.tb = (uint64_t)val2;
            last_call.a = (uint64_t)val3;
            last_call.b = (uint64_t)val4;
            cpu_loop_exit_noexc(first_cpu);
        }
    }
}


void call_5p_check_cpu_exit(void(*func)(void*,void*,void*,void*,void*), void* val, void* val2, void* val3, void* val4, void* val5){
    if (last_call.valid){
        if (last_call.n == 5 && last_call.func == (uint64_t)func && last_call.cpu == (uint64_t)val && last_call.a == (uint64_t)val3 && last_call.b == (uint64_t)val4 && last_call.c == (uint64_t)val5){
            TranslationBlock *tb = (TranslationBlock *)last_call.tb;
            TranslationBlock *tb2 = (TranslationBlock *)val2;
            if (last_call.tb == (uint64_t)val2 || (tb2 != NULL && tb != NULL && tb->pc == tb2->pc)){
                last_call.valid = false;
            }
        }
    }else{
        func(val, val2, val3, val4, val5);
        if (panda_exit_cpu() && qemu_in_vcpu_thread() && first_cpu->running){
            printf("exit loop inserting %lx\n", (long unsigned int)(void*)func);
            last_call.valid = true;
            last_call.n = (uint64_t)5;
            last_call.func = (uint64_t)func;
            last_call.cpu = (uint64_t)val;
            last_call.tb = (uint64_t)val2;
            last_call.a = (uint64_t)val3;
            last_call.b = (uint64_t)val4;
            last_call.c = (uint64_t)val5;
            cpu_loop_exit_noexc(first_cpu);
        }
    }
}



}
