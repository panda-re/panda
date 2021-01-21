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
#include <iostream>
#include <unordered_map>
#include <osi/osi_types.h>
#include <vector>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
#include "hooks_int_fns.h"
#include "dynamic_symbols/dynamic_symbols_int_fns.h"
}


using namespace std;

/***************************
 * PANDA_CB_BEFORE_BLOCK_TRANSLATE,// Before translating each basic block
PANDA_CB_BEFORE_TCG_CODEGEN,    // Before host codegen of each basic block.
PANDA_CB_AFTER_BLOCK_TRANSLATE, // After translating each basic block
PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT,    // Before executing each basic block (with option to invalidate, may trigger retranslation)
PANDA_CB_BEFORE_BLOCK_EXEC,     // Before executing each basic block
PANDA_CB_AFTER_BLOCK_EXEC,      // After executing each basic block
 */

// Mapping of addresses to hook functions
vector<struct hook> temp_before_tcg_codegen_hooks;
vector<struct hook> temp_before_block_translate_hooks;
vector<struct hook> temp_after_block_translate_hooks;
vector<struct hook> temp_before_block_exec_invalidate_opt_hooks;
vector<struct hook> temp_before_block_exec_hooks;
vector<struct hook> temp_after_block_exec_hooks;
vector<struct hook> before_tcg_codegen_hooks;
vector<struct hook> before_block_translate_hooks;
vector<struct hook> after_block_translate_hooks;
vector<struct hook> before_block_exec_invalidate_opt_hooks;
vector<struct hook> before_block_exec_hooks;
vector<struct hook> after_block_exec_hooks;

// Callback object
panda_cb before_tcg_codegen_callback;
panda_cb before_block_translate_callback;
panda_cb after_block_translate_callback;
panda_cb before_block_exec_invalidate_opt_callback;
panda_cb before_block_exec_callback;
panda_cb after_block_exec_callback;

// Handle to self
void* self = NULL;

// Enable and disable callbacks
void enable_hooking() {
    assert(self != NULL);
    panda_enable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, before_tcg_codegen_callback);
    panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_callback);
    panda_enable_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, after_block_translate_callback);
    panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt_callback);
    panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, before_block_exec_callback);
    panda_enable_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, after_block_exec_callback);
}

void disable_hooking() {
    assert(self != NULL);
    panda_disable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, before_tcg_codegen_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_callback);
    panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, after_block_translate_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, before_block_exec_callback);
    panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, after_block_exec_callback);
}

vector<hooks_panda_cb> symbols_to_handle;

void handle_hook_return (CPUState *cpu, struct hook_symbol_resolve *sh, struct symbol s, OsiModule* m){
    int id = sh->id;
    hooks_panda_cb resolved = symbols_to_handle[id];
    struct hook new_hook;
    target_ulong offset = s.address;
    new_hook.start_addr = offset;
    new_hook.end_addr = offset;
    new_hook.asid = panda_current_asid(cpu);
    new_hook.type = PANDA_CB_BEFORE_BLOCK_EXEC; 
    new_hook.cb = resolved;
    new_hook.enabled = true;
    printf("handle_hook_return\n");
    add_hook(&new_hook);
}

bool first_require = false;

void add_symbol_hook(struct symbol_hook* h){
    if (!first_require){
        panda_require("dynamic_symbols");
        first_require = true;
    }
    struct hook_symbol_resolve sh;
    sh.enabled = true;
    sh.cb = handle_hook_return;
    symbols_to_handle.push_back(h->cb);
    sh.id = symbols_to_handle.size() - 1;
    strncpy((char*) &sh.name, (char*) &h->name, MAX_PATH_LEN);
    strncpy((char*) &sh.section,(char*) &h->section, MAX_PATH_LEN);
    void* dynamic_symbols = panda_get_plugin_by_name("dynamic_symbols");
    if (dynamic_symbols != NULL){
        void (*hook_symbol_resolution_dlsym)(struct hook_symbol_resolve*) = (void(*)(struct hook_symbol_resolve*)) dlsym(dynamic_symbols, "hook_symbol_resolution");
        if ((void*)hook_symbol_resolution_dlsym != NULL) {
            hook_symbol_resolution_dlsym(&sh);
        }
    }
}

bool vector_contains_struct(vector<struct hook> vh, struct hook* new_hook){
    for (auto &h: vh)
        if (memcmp(&h, &new_hook, sizeof(struct hook)) == 0)
        if (h.start_addr == new_hook->start_addr && h.end_addr == new_hook->end_addr && h.asid == new_hook->asid && h.type == new_hook->type && h.enabled == new_hook->enabled)
            return true;
    return false;
}


void add_hook(struct hook* h) {
    switch (h->type){
        case PANDA_CB_BEFORE_TCG_CODEGEN:
            if (!vector_contains_struct(before_tcg_codegen_hooks, h) && !vector_contains_struct(temp_before_tcg_codegen_hooks, h)){
                temp_before_tcg_codegen_hooks.push_back(*h);
                panda_enable_callback(self,PANDA_CB_BEFORE_TCG_CODEGEN,before_tcg_codegen_callback);
            }
            break;
        case PANDA_CB_BEFORE_BLOCK_TRANSLATE:
            if (!vector_contains_struct(before_block_translate_hooks, h) && !vector_contains_struct(temp_before_block_translate_hooks, h)){
                temp_before_block_translate_hooks.push_back(*h); 
                panda_enable_callback(self,PANDA_CB_BEFORE_BLOCK_TRANSLATE,before_block_translate_callback);
            }
            break;
        case PANDA_CB_AFTER_BLOCK_TRANSLATE:
            if (!vector_contains_struct(after_block_translate_hooks, h) && !vector_contains_struct(temp_after_block_translate_hooks, h)){
                temp_after_block_translate_hooks.push_back(*h); 
                panda_enable_callback(self,PANDA_CB_AFTER_BLOCK_TRANSLATE,after_block_translate_callback);
            }
            break;
        case PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT:
            if (!vector_contains_struct(before_block_exec_invalidate_opt_hooks, h) && !vector_contains_struct(temp_before_block_exec_invalidate_opt_hooks, h)){
                temp_before_block_exec_invalidate_opt_hooks.push_back(*h);
                panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT,before_block_exec_invalidate_opt_callback);
            }
            break;
        case PANDA_CB_BEFORE_BLOCK_EXEC:
            if (!vector_contains_struct(before_block_exec_hooks, h) && !vector_contains_struct(temp_before_block_exec_hooks, h)){
                printf("adding bbe hook\n");
                temp_before_block_exec_hooks.push_back(*h); 
                panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC,before_block_exec_callback);
            }
            break;
        case PANDA_CB_AFTER_BLOCK_EXEC:
            if (!vector_contains_struct(after_block_exec_hooks, h) && !vector_contains_struct(temp_after_block_exec_hooks, h)){
                temp_after_block_exec_hooks.push_back(*h); 
                panda_enable_callback(self, PANDA_CB_AFTER_BLOCK_EXEC,after_block_exec_callback);
            }
            break;
        default:
            printf("couldn't find hook type. Invalid\n");
    }
}


void cb_before_tcg_codegen_callback(CPUState *cpu, TranslationBlock *tb) {
    if (!temp_before_tcg_codegen_hooks.empty()){
        for (auto &hook: temp_before_tcg_codegen_hooks) {
            before_tcg_codegen_hooks.push_back(hook);
        }
        temp_before_tcg_codegen_hooks.clear();
    }
    if (before_tcg_codegen_hooks.empty()){
        panda_disable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, before_tcg_codegen_callback);
        return;
    }
    target_ulong asid = panda_current_asid(cpu);
    bool in_kernel = panda_in_kernel(cpu);
    vector<struct hook>::iterator it = before_tcg_codegen_hooks.begin();
    while(it != before_tcg_codegen_hooks.end()){
        auto h = *it;
        if (h.enabled){
            if (h.asid == 0 || h.asid == asid){
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){
                    if ((h.start_addr <= tb->pc && tb->pc <= h.end_addr) ||
                        (h.start_addr <= tb->pc + tb->size && tb->pc + tb->size <= h.end_addr) || 
                        (h.start_addr <= tb->pc && tb->pc + tb->size <= h.end_addr)){
                        (*(h.cb.before_tcg_codegen))(cpu, tb, &h);
                        if (!h.enabled){
                            it = before_tcg_codegen_hooks.erase(it);
                            continue;
                        }
                    }
                }
            }
        }
        ++it;
    }
}


void cb_before_block_translate_callback(CPUState *cpu, target_ptr_t pc) {
    if (!temp_before_block_translate_hooks.empty()){
        for (auto &hook: temp_before_block_translate_hooks) {
            before_block_translate_hooks.push_back(hook);
        }
        temp_before_block_translate_hooks.clear();
    }
    if (before_block_translate_hooks.empty()){
        panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_callback);
        return;
    }
    target_ulong asid = panda_current_asid(cpu);
    bool in_kernel = panda_in_kernel(cpu);
    vector<struct hook>::iterator it = before_block_translate_hooks.begin();
    while(it != before_block_translate_hooks.end()){
        auto h = *it;
        if (h.enabled){
            if (h.asid == 0 || h.asid == asid){
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){
                    if (h.start_addr <= pc && pc <= h.end_addr){
                        (*(h.cb.before_block_translate))(cpu, pc, &h);
                        if (!h.enabled){
                            it = before_block_translate_hooks.erase(it);
                            continue;
                        }
                    }
                }
            }
        }
        ++it;
    }
}


void cb_after_block_translate_callback(CPUState *cpu, TranslationBlock *tb) {
    if (!temp_after_block_translate_hooks.empty()){
        for (auto &hook: temp_after_block_translate_hooks) {
            after_block_translate_hooks.push_back(hook);
        }
        temp_after_block_translate_hooks.clear();
    }
    if (after_block_translate_hooks.empty()){
        panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, after_block_translate_callback);
        return;
    }
    target_ulong asid = panda_current_asid(cpu);
    bool in_kernel = panda_in_kernel(cpu);
    vector<struct hook>::iterator it = after_block_translate_hooks.begin();
    while(it != after_block_translate_hooks.end()){
        auto h = *it;
        if (h.enabled){
            if (h.asid == 0 || h.asid == asid){
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){
                    if ((h.start_addr <= tb->pc && tb->pc <= h.end_addr) ||
                        (h.start_addr <= tb->pc + tb->size && tb->pc + tb->size <= h.end_addr) || 
                        (h.start_addr <= tb->pc && tb->pc + tb->size <= h.end_addr)){
                        (*(h.cb.after_block_translate))(cpu, tb, &h);
                        if (!h.enabled){
                            it = after_block_translate_hooks.erase(it);
                            continue;
                        }
                    }
                }
            }
        }
        ++it;
    }
}


bool cb_before_block_exec_invalidate_opt_callback(CPUState *cpu, TranslationBlock *tb) {
    bool ret = false;
    if (!temp_before_block_exec_invalidate_opt_hooks.empty()){
        for (auto &hook: temp_before_block_exec_invalidate_opt_hooks) {
            before_block_exec_invalidate_opt_hooks.push_back(hook);
        }
        temp_before_block_exec_invalidate_opt_hooks.clear();
    }
    if (before_block_exec_invalidate_opt_hooks.empty()){
        panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt_callback);
        return ret;
    }
    target_ulong asid = panda_current_asid(cpu);
    bool in_kernel = panda_in_kernel(cpu);
    vector<struct hook>::iterator it = before_block_exec_invalidate_opt_hooks.begin();
    while(it != before_block_exec_invalidate_opt_hooks.end()){
        auto h = *it;
        if (h.enabled){
            if (h.asid == 0 || h.asid == asid){
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){
                    if ((h.start_addr <= tb->pc && tb->pc <= h.end_addr) ||
                        (h.start_addr <= tb->pc + tb->size && tb->pc + tb->size <= h.end_addr) || 
                        (h.start_addr <= tb->pc && tb->pc + tb->size <= h.end_addr)){
                        ret |= (*(h.cb.before_block_exec_invalidate_opt))(cpu, tb, &h);
                        if (!h.enabled){
                            it = before_block_exec_invalidate_opt_hooks.erase(it);
                            continue;
                        }

                    }
                }
            }
        }
        ++it;
    }
    return ret;
}


void cb_before_block_exec_callback(CPUState *cpu, TranslationBlock *tb) {
    if (!temp_before_block_exec_hooks.empty()){
        for (auto &hook: temp_before_block_exec_hooks) {
            before_block_exec_hooks.push_back(hook);
        }
        temp_before_block_exec_hooks.clear();
    }
    if (before_block_exec_hooks.empty()){
        panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, before_block_exec_callback);
        return;
    }
    target_ulong asid = panda_current_asid(cpu);
    bool in_kernel = panda_in_kernel(cpu);
    vector<struct hook>::iterator it = before_block_exec_hooks.begin();
    while(it != before_block_exec_hooks.end()){
        auto h = *it;
        if (h.enabled){
            if (h.asid == 0 || h.asid == asid){
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){
                    if ((h.start_addr <= tb->pc && tb->pc <= h.end_addr) ||
                        (h.start_addr <= tb->pc + tb->size && tb->pc + tb->size <= h.end_addr) || 
                        (h.start_addr <= tb->pc && tb->pc + tb->size <= h.end_addr)){
                        (*(h.cb.before_block_exec))(cpu, tb, &h);
                        if (!h.enabled){
                            printf("disabling with size %d\n", (int) before_block_exec_hooks.size());
                            it = before_block_exec_hooks.erase(it);
                            printf("disabled with size %d\n", (int) before_block_exec_hooks.size());
                            continue;
                        }
    
                    }
                }
            }
        }
        ++it;
    }
}


void cb_after_block_exec_callback(CPUState *cpu, TranslationBlock *tb, uint8_t exitCode) {
    if (!temp_after_block_exec_hooks.empty()){
        for (auto &hook: temp_after_block_exec_hooks) {
            after_block_exec_hooks.push_back(hook);
        }
        temp_after_block_exec_hooks.clear();
    }
    if (after_block_exec_hooks.empty()){
        panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, after_block_exec_callback);
        return;
    }
    target_ulong asid = panda_current_asid(cpu);
    bool in_kernel = panda_in_kernel(cpu);
    vector<struct hook>::iterator it = after_block_exec_hooks.begin();
    while(it != after_block_exec_hooks.end()){
        auto h = *it;
        if (h.enabled){
            if (h.asid == 0 || h.asid == asid){
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){
                    if ((h.start_addr <= tb->pc && tb->pc < h.end_addr) ||
                        (h.start_addr <= tb->pc + tb->size && tb->pc + tb->size < h.end_addr) || 
                        (h.start_addr <= tb->pc && h.end_addr <= tb->pc + tb->size)){
                        (*(h.cb.after_block_exec))(cpu, tb, exitCode, &h);
                        if (!h.enabled){
                            printf("removing hook\n");
                            it = after_block_exec_hooks.erase(it);
                            continue;
                        }

                    }
                }
            }
        }
        ++it;
    }
}



bool init_plugin(void *_self) {
    // On init, register a callback but don't enable it
    self = _self;
    panda_enable_precise_pc();
    panda_disable_tb_chaining();

    before_tcg_codegen_callback.before_tcg_codegen = cb_before_tcg_codegen_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, before_tcg_codegen_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, before_tcg_codegen_callback);
    
    before_block_translate_callback.before_block_translate = cb_before_block_translate_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_callback);
    
    
    after_block_translate_callback.after_block_translate = cb_after_block_translate_callback;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, after_block_translate_callback);
    panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, after_block_translate_callback);
    
    
    before_block_exec_invalidate_opt_callback.before_block_exec_invalidate_opt = cb_before_block_exec_invalidate_opt_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt_callback);
    
    
    before_block_exec_callback.before_block_exec = cb_before_block_exec_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, before_block_exec_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, before_block_exec_callback);
    
    
    after_block_exec_callback.after_block_exec = cb_after_block_exec_callback;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, after_block_exec_callback);
    panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, after_block_exec_callback);

    return true;
}

void uninit_plugin(void *self) {
    disable_hooking();
}
