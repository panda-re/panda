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
#include "panda/plugin_api.h"
#include "panda/common.h"
#include "panda/tcg-utils.h"
#include <iostream>
#include <unordered_map>
#include <osi/osi_types.h>
#include "exec/tb-hash.h"
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
    return tie(a.addr, a.asid, a.type, a.cb.before_block_exec) < tie(b.addr, b.asid, b.type, b.cb.before_block_exec);//, b.km, b.enabled);
    //if (a == b){, a.km, a.enabled)
    //    return false;
    //}
    //NOT_EQUAL_RETURN_COND(a.addr, b.addr);
    //NOT_EQUAL_RETURN_COND(a.asid, b.asid);
    //NOT_EQUAL_RETURN_COND(a.type, b.type);
    //NOT_EQUAL_RETURN_COND((void*)a.cb.before_block_exec, (void*)b.cb.before_block_exec);
    //NOT_EQUAL_RETURN_COND(a.km, b.km);
    //NOT_EQUAL_RETURN_COND(a.enabled, b.enabled);
    //NOT_EQUAL_RETURN_COND(&a, &b);
    //return false;
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
        temp_## TYPE ## _hooks.push_back(*h); \
        panda_enable_callback(self, PANDA_CB_ ## TYPE_UPPER , TYPE ## _callback); \
        break;

bool first_tb_chaining = false;

static inline void flush_tb_if_block_in_cache(CPUState* cpu, target_ulong pc){
    assert(cpu != (CPUState*)NULL && "Cannot register TCG-based hooks before guest is created. Try this in after_machine_init CB");
    TranslationBlock *tb = cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (tb && tb->pc == pc){
        tb_lock();
        tb_phys_invalidate(tb, -1);
        tb_free(tb);
        tb_unlock();
    }
}

void add_hook(struct hook* h) {
    if (h->type != PANDA_CB_BEFORE_TCG_CODEGEN && !first_tb_chaining){
        // if we ever register a non tcg_codegen we must disable tb chaining
        panda_disable_tb_chaining();
        first_tb_chaining = true;
    }
    if (h->type == PANDA_CB_BEFORE_TCG_CODEGEN){
        flush_tb_if_block_in_cache(first_cpu, h->addr);
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


// TODO remove get_cpu()
#define MAKE_HOOK_FN_START(UPPER_CB_NAME, NAME, VALUE, PC) \
    if (unlikely(! temp_ ## NAME ## _hooks .empty())){ \
        for (auto &h: temp_ ## NAME ## _hooks) { \
            NAME ## _hooks[h.asid].insert(h); \
        } \
        temp_ ## NAME ## _hooks .clear(); \
    } \
    if (unlikely(NAME ## _hooks .empty())){ \
        panda_disable_callback(self, PANDA_CB_ ## UPPER_CB_NAME, NAME ## _callback); \
        return VALUE; \
    } \
    CPUState *_cpu = get_cpu(); \
    target_ulong asid = panda_current_asid(_cpu); \
    bool in_kernel = panda_in_kernel(_cpu); \
    struct hook hook_container; \
    memset(&hook_container, 0, sizeof(hook_container)); \
    hook_container.addr = PC; \
    set<struct hook>::iterator it;

#define LOOP_ASID_CHECK(NAME, EXPR, COMPARATOR_TO_BLOCK)\
    it = NAME ## _hooks[asid].lower_bound(hook_container); \
    while(it != NAME ## _hooks[asid].end() && it->addr COMPARATOR_TO_BLOCK){ \
        auto h = (hook*)&(*it); \
        if (likely(h->enabled)){ \
            if (h->asid == 0 || h->asid == asid){ \
                if (h->km == MODE_ANY || (in_kernel && h->km == MODE_KERNEL_ONLY) || (!in_kernel && h->km == MODE_USER_ONLY)){ \
                    EXPR \
                    if (!h->enabled){ \
                        it = NAME ## _hooks[asid].erase(it); \
                        continue; \
                    } \
                    /*memcpy((void*)&(*it), (void*)&h, sizeof(struct hook));*/ \
                } \
            } \
        } \
        ++it; \
    } 

#define HOOK_GENERIC_RET_EXPR(EXPR, UPPER_CB_NAME, NAME, VALUE, COMPARATOR_TO_BLOCK, PC) \
    MAKE_HOOK_FN_START(UPPER_CB_NAME, NAME, VALUE, PC) \
    LOOP_ASID_CHECK(NAME, EXPR, COMPARATOR_TO_BLOCK)

#define MAKE_HOOK_VOID(UPPER_CB_NAME, NAME, PASSED_ARGS, PC, ...) \
void cb_ ## NAME ## _callback PASSED_ARGS { \
    HOOK_GENERIC_RET_EXPR( (*(h->cb.NAME))(__VA_ARGS__);, UPPER_CB_NAME, NAME, , == hook_container.addr, PC) \
}

#define MAKE_HOOK_BOOL(UPPER_CB_NAME, NAME, PASSED_ARGS, PC, ...) \
bool cb_ ## NAME ## _callback PASSED_ARGS { \
    bool ret = false; \
    HOOK_GENERIC_RET_EXPR(ret |= (*(h->cb.NAME))(__VA_ARGS__);, UPPER_CB_NAME, NAME, false, == hook_container.addr, PC) \
    return ret; \
}
    
void cb_tcg_codegen_middle_filter(CPUState* cpu, TranslationBlock *tb) {
    HOOK_GENERIC_RET_EXPR(/*printf("calling %llx from %llx with hook %llx guest_pc %llx\n", (long long unsigned int) panda_current_pc(cpu), (long long unsigned int)tb->pc, (long long unsigned int)h->addr, (long long unsigned int)cpu->panda_guest_pc);*/ (*(h->cb.before_tcg_codegen))(cpu, tb, h);, BEFORE_TCG_CODEGEN, before_tcg_codegen, , < tb->pc + tb->size, panda_current_pc(cpu) );
}

void cb_before_tcg_codegen_callback (CPUState* cpu, TranslationBlock *tb) {
    //target_ulong pc  = panda_current_pc(cpu);
    
    HOOK_GENERIC_RET_EXPR(TCGOp *op = find_guest_insn_by_addr(h->addr);insert_call(&op, cb_tcg_codegen_middle_filter, cpu, tb);, BEFORE_TCG_CODEGEN, before_tcg_codegen, , < tb->pc + tb->size, tb->pc)
}


MAKE_HOOK_VOID(BEFORE_BLOCK_TRANSLATE, before_block_translate, (target_ulong pc), panda_current_pc2(), pc, h)

MAKE_HOOK_VOID(AFTER_BLOCK_TRANSLATE, after_block_translate, (CPUState *cpu, TranslationBlock *tb), tb->pc, cpu, tb, h)

MAKE_HOOK_BOOL(BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt, (TranslationBlock* tb), tb->pc, tb, h)

MAKE_HOOK_VOID(BEFORE_BLOCK_EXEC, before_block_exec, (TranslationBlock *tb), tb->pc, tb, h)

MAKE_HOOK_VOID(AFTER_BLOCK_EXEC, after_block_exec, (CPUState *cpu, TranslationBlock *tb, uint8_t exitCode), tb->pc, cpu, tb, exitCode, h)


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
