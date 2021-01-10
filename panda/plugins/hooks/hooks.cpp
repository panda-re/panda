/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano               andrew.fasano@ll.mit.edu
 *  Nick Gregory                ngregory@nyu.edu
 *  Luke Craig                  luke.craig@ll.mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "hooks_int_fns.h"
#include <iostream>
#include <unordered_map>
#include <vector>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

using namespace std;

// Hooking framework to execute code before guest executes given basic block

// Mapping of addresses to hook functions
vector<struct hook> hooks;

// Callback object
panda_cb c_callback;

// Handle to self
void* self = NULL;

// Enable and disable callbacks
void enable_hooking() {
  assert(self != NULL);
  panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
}
void disable_hooking() {
  assert(self != NULL);
  panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
}

struct hook* add_hook(struct hook* h) {

    if (!panda_is_callback_enabled(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback)) enable_hooking(); // Ensure our panda callback is enabled when we add a hook
    hooks.push_back(*h);

    printf("Adding hook from guest 0x" TARGET_FMT_lx " to host %p\n", h->start_addr, &hooks[hooks.size() -1]);
    return &hooks[hooks.size() -1];
}


// The panda callback to determine if we should call a python callback
bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb) {
    // Call any callbacks registered at this PC. Any called callback may invalidate the translation block
 
    bool ret = false;
    target_ulong asid = panda_current_asid(cpu);

    for (auto& hook: hooks){
        if (hook.enabled){
            if (hook.asid == 0 || hook.asid == asid){
                if (hook.start_addr <= tb->pc && tb->pc <= hook.start_addr + hook.end_addr){
                    ret |= (*(hook.cb))(cpu, tb, &hook);
                }
            }
        }
    }
    return ret;
}


bool init_plugin(void *_self) {
    // On init, register a callback but don't enable it
    self = _self;

    panda_disable_tb_chaining();

    c_callback.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);

    return true;
}

void uninit_plugin(void *self) {}
