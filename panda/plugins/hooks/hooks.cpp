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
#include "panda/tcg-utils.h"
#include <iostream>
#include <unordered_map>
#include <osi/osi_types.h>
#include <set>
#include <vector>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
#include "dynamic_symbols/dynamic_symbols_int_fns.h"
#include "hooks_int_fns.h"
}

extern bool panda_please_flush_tb;

using namespace std;

bool operator==(const struct hook &a, const struct hook &b){
    return memcmp(&a, &b, sizeof(struct hook)) == 0;
}

#define NOT_EQUAL_RETURN_COND(A, B)  do {if (A != B) { return A < B;}} while (0)
//
/*
 * The set wants to know if our elements are the same. We only want
 * this to happen in the case that our structs are actual duplicates.
 * Otherwise we want them ordered by address and then asid and so on.
 */
bool operator<(const struct hook &a, const struct hook &b){
    //printf("comparing %llx %llx\n", (long long unsigned int) a.addr, (long long unsigned int) b.addr);
    if (a == b){
        return false;
    }
    NOT_EQUAL_RETURN_COND(a.addr, b.addr);
    NOT_EQUAL_RETURN_COND(a.asid, b.asid);
    NOT_EQUAL_RETURN_COND(a.type, b.type);
    NOT_EQUAL_RETURN_COND((void*)a.cb.before_block_exec, (void*)b.cb.before_block_exec);
    NOT_EQUAL_RETURN_COND(a.km, b.km);
    NOT_EQUAL_RETURN_COND(a.enabled, b.enabled);
    NOT_EQUAL_RETURN_COND(&a, &b);
    return false;
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

vector<pair<hooks_panda_cb, panda_cb_type>> symbols_to_handle;

void handle_hook_return (CPUState *cpu, struct hook_symbol_resolve *sh, struct symbol s, OsiModule* m){
    int id = sh->id;
    pair<hooks_panda_cb,panda_cb_type> resolved = symbols_to_handle[id];
    //printf("handle_hook_return @ 0x%llx for \"%s\" in \"%s\" @ 0x%llx ASID: 0x%llx offset: 0x%llx\n", (long long unsigned int)rr_get_guest_instr_count(), s.name, s.section, (long long unsigned int) s.address, (long long unsigned int) panda_current_asid(cpu), (long long unsigned int) s.address - m->base);
    struct hook new_hook;
    new_hook.addr = s.address;
    new_hook.asid = panda_current_asid(cpu);
    new_hook.type = resolved.second; 
    new_hook.km = MODE_USER_ONLY;
    new_hook.cb = resolved.first;
    new_hook.enabled = true;
    memcpy(&new_hook.sym, &s, sizeof(struct symbol));
    add_hook(&new_hook);
}

void add_symbol_hook(struct symbol_hook* h){
    //printf("add_symbol_hook\n");
    pair<hooks_panda_cb, panda_cb_type> p (h->cb, h->type);
    struct hook_symbol_resolve sh;
    sh.enabled = true;
    sh.cb = handle_hook_return;
    symbols_to_handle.push_back(p);
    sh.id = symbols_to_handle.size() - 1;
    strncpy((char*) &sh.procname, (char*) & h->procname, MAX_PATH_LEN);
    strncpy((char*) &sh.name, (char*) &h->name, MAX_PATH_LEN);
    strncpy((char*) &sh.section,(char*) &h->section, MAX_PATH_LEN);
    void* dynamic_symbols = panda_get_plugin_by_name("dynamic_symbols");
    if (dynamic_symbols == NULL){
        panda_require("dynamic_symbols");
        dynamic_symbols = panda_get_plugin_by_name("dynamic_symbols");
    }
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

bool first_tb_chaining = false;

void add_hook(struct hook* h) {
    if (h->type != PANDA_CB_BEFORE_TCG_CODEGEN && !first_tb_chaining){
        // if we ever register a non tcg_codegen we must disable tb chaining
        panda_disable_tb_chaining();
        first_tb_chaining = true;
    }
    if (h->type == PANDA_CB_BEFORE_TCG_CODEGEN){
        panda_please_flush_tb = true;
    }
    switch (h->type){
        ADD_CALLBACK_TYPE(before_tcg_codegen, BEFORE_TCG_CODEGEN)
        ADD_CALLBACK_TYPE(before_block_translate, BEFORE_BLOCK_TRANSLATE)
        ADD_CALLBACK_TYPE(after_block_translate, AFTER_BLOCK_TRANSLATE)
        ADD_CALLBACK_TYPE(before_block_exec_invalidate_opt, BEFORE_BLOCK_EXEC_INVALIDATE_OPT)
        ADD_CALLBACK_TYPE(before_block_exec, BEFORE_BLOCK_EXEC)
        ADD_CALLBACK_TYPE(after_block_exec, AFTER_BLOCK_EXEC)
        default:
            printf("couldn't find hook type. Invalid %d\n", (int) h->type);
    }
}


#define MAKE_HOOK_FN_START(UPPER_CB_NAME, NAME, VALUE) \
    if (unlikely(! temp_ ## NAME ## _hooks .empty())){ \
        for (auto &h: temp_ ## NAME ## _hooks) { \
            auto pair = NAME ## _hooks[h.asid].insert(h); \
            if (!pair.second) { \
                printf("failed add\n");  \
                printf(*pair.first == (const hook) h ? "true\n" : "false\n"); \
            } \
        } \
        temp_ ## NAME ## _hooks .clear(); \
    } \
    if (unlikely(NAME ## _hooks .empty())){ \
        panda_disable_callback(self, PANDA_CB_ ## UPPER_CB_NAME, NAME ## _callback); \
        return VALUE; \
    } \
    target_ulong asid = panda_current_asid(cpu); \
    bool in_kernel = panda_in_kernel(cpu); \
    struct hook hook_container; \
    memset(&hook_container, 0, sizeof(hook_container)); \
    hook_container.addr = panda_current_pc(cpu); \
    set<struct hook>::iterator it;

#define LOOP_ASID_CHECK(NAME, EXPR)\
    it = NAME ## _hooks[asid].lower_bound(hook_container); \
    while(it != NAME ## _hooks[asid].end() && it->addr == hook_container.addr){ \
        auto h = *it; \
        if (likely(h.enabled)){ \
            if (h.asid == 0 || h.asid == asid){ \
                if (h.km == MODE_ANY || (in_kernel && h.km == MODE_KERNEL_ONLY) || (!in_kernel && h.km == MODE_USER_ONLY)){ \
                    EXPR \
                    if (!h.enabled){ \
                        it = NAME ## _hooks[asid].erase(it); \
                        continue; \
                    } \
                    memcpy((void*)&(*it), (void*)&h, sizeof(struct hook)); \
                } \
            } \
        } \
        ++it; \
    } 

#define HOOK_GENERIC_RET_EXPR(EXPR, UPPER_CB_NAME, NAME, VALUE) \
    MAKE_HOOK_FN_START(UPPER_CB_NAME, NAME, VALUE) \
    LOOP_ASID_CHECK(NAME, EXPR) \
    asid = 0; \
    LOOP_ASID_CHECK(NAME, EXPR)

#define MAKE_HOOK_VOID(UPPER_CB_NAME, NAME, PASSED_ARGS, ...) \
void cb_ ## NAME ## _callback PASSED_ARGS { \
    HOOK_GENERIC_RET_EXPR( (*(h.cb.NAME))(__VA_ARGS__);, UPPER_CB_NAME, NAME, ) \
}

#define MAKE_HOOK_BOOL(UPPER_CB_NAME, NAME, PASSED_ARGS, ...) \
bool cb_ ## NAME ## _callback PASSED_ARGS { \
    bool ret = false; \
    HOOK_GENERIC_RET_EXPR(ret |= (*(h.cb.NAME))(__VA_ARGS__);, UPPER_CB_NAME, NAME, false) \
    return ret; \
}

void cb_tcg_codegen_middle_filter(CPUState* cpu, TranslationBlock *tb) {
    HOOK_GENERIC_RET_EXPR((*(h.cb.before_tcg_codegen))(cpu, tb, &h);, BEFORE_TCG_CODEGEN, before_tcg_codegen, );
}

void cb_before_tcg_codegen_callback (CPUState* cpu, TranslationBlock *tb) {
    TCGOp *op = find_first_guest_insn();
    HOOK_GENERIC_RET_EXPR(insert_call(&op, cb_tcg_codegen_middle_filter, cpu, tb); return;, BEFORE_TCG_CODEGEN, before_tcg_codegen, )
}

MAKE_HOOK_VOID(BEFORE_BLOCK_TRANSLATE, before_block_translate, (CPUState *cpu, target_ulong pc), cpu, pc, &h)

MAKE_HOOK_VOID(AFTER_BLOCK_TRANSLATE, after_block_translate, (CPUState *cpu, TranslationBlock *tb), cpu, tb, &h)

MAKE_HOOK_BOOL(BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt, (CPUState* cpu, TranslationBlock* tb), cpu, tb, &h)

MAKE_HOOK_VOID(BEFORE_BLOCK_EXEC, before_block_exec, (CPUState *cpu, TranslationBlock *tb), cpu, tb, &h)

MAKE_HOOK_VOID(AFTER_BLOCK_EXEC, after_block_exec, (CPUState *cpu, TranslationBlock *tb, uint8_t exitCode), cpu, tb, exitCode, &h)


#define REGISTER_AND_DISABLE_CALLBACK(SELF, NAME, NAME_UPPER)\
    NAME ## _callback. NAME  = cb_ ## NAME ## _callback; \
    panda_register_callback(SELF, PANDA_CB_ ## NAME_UPPER, NAME ## _callback); \
    panda_disable_callback(SELF, PANDA_CB_ ## NAME_UPPER, NAME ## _callback);

bool init_plugin(void *_self) {
    // On init, register a callback but don't enable it
    self = _self;
    panda_enable_precise_pc();

    REGISTER_AND_DISABLE_CALLBACK(_self, before_tcg_codegen, BEFORE_TCG_CODEGEN)
    REGISTER_AND_DISABLE_CALLBACK(_self, before_block_translate, BEFORE_BLOCK_TRANSLATE)
    REGISTER_AND_DISABLE_CALLBACK(_self, after_block_translate, AFTER_BLOCK_TRANSLATE)
    REGISTER_AND_DISABLE_CALLBACK(_self, before_block_exec_invalidate_opt, BEFORE_BLOCK_EXEC_INVALIDATE_OPT)
    REGISTER_AND_DISABLE_CALLBACK(_self, before_block_exec, BEFORE_BLOCK_EXEC)
    REGISTER_AND_DISABLE_CALLBACK(_self, after_block_exec, AFTER_BLOCK_EXEC)
    return true;
}

void uninit_plugin(void *self) {
    disable_hooking();
}