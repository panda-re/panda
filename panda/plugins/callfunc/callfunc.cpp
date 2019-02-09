/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

target_ulong when;
target_ulong target_func;
target_ulong func_args[4];
target_ulong saved_regs[16];
bool in_call = false;

static bool call_function(CPUState *env, TranslationBlock *tb) {
#ifdef TARGET_ARM
    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    if (in_call) {
        if (tb->pc == when) {
            // print out R0 (return value)
            printf("Called function " TARGET_FMT_lx " returned " TARGET_FMT_lx "\n",
                    target_func, envp->regs[0]);
            // restore registers
            memcpy(envp->regs, saved_regs, sizeof(saved_regs));
            in_call = false;
            return false;
        }
        else {
            return false;
        }
    }
    else {
        if (tb->pc == when) {
            in_call = true;
            // save registers
            memcpy(saved_regs, envp->regs, sizeof(saved_regs));
            // set up args
            envp->regs[0] = func_args[0];
            envp->regs[1] = func_args[1];
            envp->regs[2] = func_args[2];
            envp->regs[3] = func_args[3];
            // set LR = when
            envp->regs[14] = when;
            // set PC = target_func
            envp->regs[15] = target_func;
            return true;
        }
        else {
            return false;
        }
    }
#else
    return false;
#endif
}

// Not handled:
//  - What if target_func tries to call "when"
//  - What about recursive calls
//  - What if when is not the start of a basic block
//  - What if we have more than 4 parameters
//  - CPU state other than the regs
bool init_plugin(void *self) {
    panda_cb pcb;
    pcb.before_block_exec_invalidate_opt = call_function;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    
    panda_arg_list *args = panda_get_args("callfunc");
    when = panda_parse_ulong_req(args, "when", "the PC at which to call our function");
    target_func = panda_parse_ulong_req(args, "func", "the function to call");
    func_args[0] = panda_parse_ulong_opt(args, "arg1", 0, "the first function argument");
    func_args[1] = panda_parse_ulong_opt(args, "arg2", 0, "the second function argument");
    func_args[2] = panda_parse_ulong_opt(args, "arg3", 0, "the third function argument");
    func_args[3] = panda_parse_ulong_opt(args, "arg4", 0, "the fourth function argument");

    return true;
}

void uninit_plugin(void *self) { }
