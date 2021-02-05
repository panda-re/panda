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
#include <set>
#include <vector>
#include "hook_macros.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
#include "dynamic_symbols/dynamic_symbols_int_fns.h"
#include "hooks_int_fns.h"
}

using namespace std;

bool operator<(const struct hook &a, const struct hook &b){
    return a.addr < b.addr;
}

#define SUPPORT_CALLBACK_TYPE(name) \
    vector<struct hook> temp_ ## name ## _hooks; \
    unordered_map<target_ulong, set<struct hook>> name ## _hooks; \
    panda_cb name ## _callback;

SUPPORT_CALLBACK_TYPE(before_tcg_codegen)
SUPPORT_CALLBACK_TYPE(before_block_translate)
SUPPORT_CALLBACK_TYPE(after_block_translate)
SUPPORT_CALLBACK_TYPE(before_block_exec_invalidate_opt)
SUPPORT_CALLBACK_TYPE(before_block_exec)
SUPPORT_CALLBACK_TYPE(after_block_exec)

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
    //printf("handle_hook_return @ 0x%llx for \"%s\" in \"%s\" @ 0x%llx ASID: 0x%llx\n", (long long unsigned int)rr_get_guest_instr_count(), s.name, s.section, (long long unsigned int) s.address, (long long unsigned int) panda_current_asid(cpu));
    struct hook new_hook;
    new_hook.addr = s.address;
    new_hook.asid = panda_current_asid(cpu);
    new_hook.type = PANDA_CB_BEFORE_BLOCK_EXEC; 
    new_hook.km = MODE_USER_ONLY;
    new_hook.cb = resolved;
    new_hook.enabled = true;
    memcpy(&new_hook.sym, &s, sizeof(struct symbol));
    add_hook(&new_hook);
}

bool first_require = false;

void add_symbol_hook(struct symbol_hook* h){
    //printf("add_symbol_hook\n");
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

bool set_contains_struct(unordered_map<target_ulong, set<struct hook>> vh, struct hook* new_hook){
    return vh[new_hook->asid].find(*new_hook) != vh[new_hook->asid].end();
}

bool vector_contains_struct(vector<struct hook> vh, struct hook* new_hook){
    for (auto &h: vh){
        if (memcmp(&h, new_hook, sizeof(struct hook)) == 0){
            return true;
        }}
    return false;
}

#define ADD_CALLBACK_TYPE(TYPE, TYPE_UPPER) \
    case PANDA_CB_ ## TYPE_UPPER: \
        if (!set_contains_struct(TYPE ## _hooks, h) && !vector_contains_struct(temp_## TYPE ## _hooks, h)){ \
            temp_## TYPE ## _hooks.push_back(*h); \
            panda_enable_callback(self, PANDA_CB_ ## TYPE_UPPER , TYPE ## _callback); \
        } \
        break;


void add_hook(struct hook* h) {
    switch (h->type){
        ADD_CALLBACK_TYPE(before_tcg_codegen, BEFORE_TCG_CODEGEN)
        ADD_CALLBACK_TYPE(before_block_translate, BEFORE_BLOCK_TRANSLATE)
        ADD_CALLBACK_TYPE(after_block_translate, AFTER_BLOCK_TRANSLATE)
        ADD_CALLBACK_TYPE(before_block_exec_invalidate_opt, BEFORE_BLOCK_EXEC_INVALIDATE_OPT)
        ADD_CALLBACK_TYPE(before_block_exec, BEFORE_BLOCK_EXEC)
        ADD_CALLBACK_TYPE(after_block_exec, AFTER_BLOCK_EXEC)
        default:
            printf("couldn't find hook type. Invalid\n");
    }
}


#define MAKE_HOOK_FN_START(upper_cb_name, temp_name_hooks, name_hooks, name, callback, value) \
    if (unlikely(! temp_name_hooks .empty())){ \
        for (auto &h: temp_name_hooks) { \
            name_hooks[h.asid].insert(h); \
        } \
        temp_name_hooks .clear(); \
    } \
    if (unlikely(name_hooks .empty())){ \
        panda_disable_callback(self, PANDA_CB_ ## upper_cb_name, callback); \
        return value; \
    } \
    target_ulong asid = panda_current_asid(cpu); \
    bool in_kernel = panda_in_kernel(cpu); \
    struct hook hook_container; \
    hook_container.addr = panda_current_pc(cpu); \
    set<struct hook>::iterator it;

#define HOOK_ASID_START(name_hooks)\
    it = name_hooks[asid].lower_bound(hook_container); \
    while(it != name_hooks[asid].end() && it->addr == hook_container.addr){ \
        auto h = *it; \
        if (likely(h.enabled)){ \
            if (h.asid == 0 || h.asid == asid){ \
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){


#define MAKE_HOOK_FN_END(name_hooks) \
                    if (!h.enabled){ \
                        it = name_hooks[asid].erase(it); \
                        continue; \
                    } \
                    memcpy((void*)&(*it), (void*)&h, sizeof(struct hook)); \
                } \
            } \
        } \
        ++it; \
    } 

#define MAKE_HOOK_VOID(upper_cb_name, name, ...) \
    MAKE_HOOK_FN_START(upper_cb_name, temp_ ## name ## _hooks, name ## _hooks, name, name ## _callback, )\
    HOOK_ASID_START(name ## _hooks) \
    (*(h.cb.name))(__VA_ARGS__); \
    MAKE_HOOK_FN_END(name ## _hooks) \
    asid = 0; \
    HOOK_ASID_START(name ## _hooks) \
    (*(h.cb.name))(__VA_ARGS__); \
    MAKE_HOOK_FN_END(name ## _hooks)

#define MAKE_HOOK_BOOL(upper_cb_name, name, ...) \
    MAKE_HOOK_FN_START(upper_cb_name, temp_ ## name ## _hooks, name ## _hooks, name, name ## _callback, false) \
    HOOK_ASID_START(name ## _hooks) \
    MAKE_HOOK_FN_END(name ## _hooks) \
    asid = 0; \
    HOOK_ASID_START(name ## _hooks) \
    ret |= (*(h.cb.name))(__VA_ARGS__); \
    MAKE_HOOK_FN_END(name ## _hooks)

void cb_before_tcg_codegen_callback(CPUState *cpu, TranslationBlock *tb){
    MAKE_HOOK_VOID(BEFORE_TCG_CODEGEN, before_tcg_codegen, cpu, tb, &h)
}

void cb_before_block_translate_callback(CPUState *cpu, target_ptr_t pc) {
    MAKE_HOOK_VOID(BEFORE_BLOCK_TRANSLATE, before_block_translate, cpu, pc, &h)
}

void cb_after_block_translate_callback(CPUState *cpu, TranslationBlock *tb) {
    MAKE_HOOK_VOID(AFTER_BLOCK_TRANSLATE, after_block_translate, cpu, tb, &h)
}

bool cb_before_block_exec_invalidate_opt_callback(CPUState *cpu, TranslationBlock *tb) {
    bool ret = false;
    MAKE_HOOK_BOOL(BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt, cpu, tb, &h)
    return ret;
}

void cb_before_block_exec_callback(CPUState *cpu, TranslationBlock *tb) {
    MAKE_HOOK_VOID(BEFORE_BLOCK_EXEC, before_block_exec, cpu, tb, &h)
}

void cb_after_block_exec_callback(CPUState *cpu, TranslationBlock *tb, uint8_t exitCode) {
    MAKE_HOOK_VOID(AFTER_BLOCK_EXEC, after_block_exec, cpu, tb, exitCode, &h)
}


#define REGISTER_AND_DISABLE_CALLBACK(NAME, NAME_UPPER)\
    NAME ## _callback. NAME  = cb_ ## NAME ## _callback; \
    panda_register_callback(self, PANDA_CB_ ## NAME_UPPER, NAME ## _callback); \
    panda_disable_callback(self, PANDA_CB_ ## NAME_UPPER, NAME ## _callback);

bool init_plugin(void *_self) {
    // On init, register a callback but don't enable it
    self = _self;
    panda_enable_precise_pc();
    panda_disable_tb_chaining();

    REGISTER_AND_DISABLE_CALLBACK(before_block_translate, BEFORE_BLOCK_TRANSLATE)
    REGISTER_AND_DISABLE_CALLBACK(before_tcg_codegen, BEFORE_TCG_CODEGEN)
    REGISTER_AND_DISABLE_CALLBACK(before_block_translate, BEFORE_BLOCK_TRANSLATE)
    REGISTER_AND_DISABLE_CALLBACK(after_block_translate, AFTER_BLOCK_TRANSLATE)
    REGISTER_AND_DISABLE_CALLBACK(before_block_exec_invalidate_opt, BEFORE_BLOCK_EXEC_INVALIDATE_OPT)
    REGISTER_AND_DISABLE_CALLBACK(before_block_exec, BEFORE_BLOCK_EXEC)
    REGISTER_AND_DISABLE_CALLBACK(after_block_exec, AFTER_BLOCK_EXEC)
    return true;
}

void uninit_plugin(void *self) {
    disable_hooking();
}