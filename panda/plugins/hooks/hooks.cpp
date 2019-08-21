/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano               andrew.fasano@ll.mit.edu
 *  Nick Gregory                ngregory@nyu.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "hooks.h"
#include <iostream>
#include <unordered_map>
#include <vector>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

// Hooking framework to execute code before guest executes given basic block

// Mapping of addresses to hook functions
std::unordered_map<target_ulong, std::vector<hook_func_t>> hooks;

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

// Can't use hook_func_t in our type because it's a c++ type and this is extern'd for c
//void add_hook(target_ulong addr, void* hook_) {
void add_hook(target_ulong addr, hook_func_t hook) {
//void add_hook(target_ulong addr, bool(*hook)(void*, void*)) {
  //hook_func_t hook = (hook_func_t)hook_;
  printf("Adding hook from guest 0x" TARGET_FMT_lx " to host %p\n", addr, hook_);

  if (!panda_is_callback_enabled(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback)) enable_hooking(); // Ensure our panda callback is enabled when we add a hook
  hooks[addr].push_back((hook_func_t(hook);
}


// The panda callback to determine if we should call a python callback
bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb) {
    // Call any callbacks registered at this PC. Any called callback may invalidate the translation block
 
    bool ret = false;

    auto func_hooks = hooks.find(tb->pc);
    if (func_hooks != hooks.end()) {
        for (auto &hook : func_hooks->second) {
            ret |= (*hook)(cpu, tb);
        }
    }

#ifdef DEBUG
    if (ret) {
        printf("Invalidating the translation block at 0x" TARGET_FMT_lx "\n", tb->pc);
    }
#endif

    return ret;
}

bool init_plugin(void *_self) {
    // On init, register a callback but don't enable it
    self = _self;

    panda_disable_tb_chaining();

    c_callback.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);

    panda_enable_memcb();

    return true;
}

void uninit_plugin(void *self) {}
