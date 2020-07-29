/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Luke Craig   luke.craig@ll.mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#include "syscalls2_errors.h"
#include <stdlib.h>
#include <stdio.h>
bool debug = false;





/*
* https://git.musl-libc.org/cgit/musl/tree/src/internal/syscall_ret.c?h=v1.1.15
*/
void catch_all_sys_return(CPUState* cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx){
    target_ulong return_value = get_syscall_retval(cpu);
    if (return_value > (target_ulong)(-4096UL)){
        target_ulong ret_value_signed = (target_ulong)( - (target_long)(return_value));
        const char* name;
        const char* err = strerror(ret_value_signed);
        if (call != NULL){
            name = call->name;
            if (debug){
                if (err != NULL){
                    printf("[syscall2_error] %s returned (%ld) %s\n", name, (uint64_t)ret_value_signed,err);
                }else{
                    printf("[syscall2_error] %s returned (%ld)\n", name, (uint64_t)ret_value_signed);
                }
            }
        }else if (ctx != NULL){
            if (debug){
                if (err != NULL){
                    printf("[syscall2_error] %d returned (%ld) %s\n", ctx->no, (uint64_t)ret_value_signed,err);
                }else{
                    printf("[syscall2_error] %d returned (%ld)\n", ctx->no, (uint64_t)ret_value_signed);
                }
            }

        }
        PPP_RUN_CB(on_get_error, cpu, pc, call, ctx, ret_value_signed, err);
    }
}


bool init_plugin(void *self) {
    panda_add_arg("syscalls2", "load-info=true");
    panda_require("syscalls2");
    assert(init_syscalls2_api());
    PPP_REG_CB("syscalls2", on_all_sys_return2, catch_all_sys_return);
    PPP_REG_CB("syscalls2", on_all_sys_return2, catch_all_sys_return);
    return true;
}

void uninit_plugin(void *self) { 
    // necesary? probably not. but it is part of the spec, so why not?
    PPP_REMOVE_CB("syscalls2", on_all_sys_return2, catch_all_sys_return);
}
