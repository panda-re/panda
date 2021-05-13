/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Luke Craig                  luke.craig@ll.mit.edu
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
#include "panda/common.h"
#include "panda/tcg-utils.h"
#include <iostream>
#include <unordered_map>
#include <osi/osi_types.h>
#include <set>
#include <queue>
#include <vector>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"
#include "dynamic_symbols/dynamic_symbols_int_fns.h"
#include "hooks_int_fns.h"
#include "exec/tb-hash.h"
#include "translate-all.h"
void hooks_flush_pc(target_ulong pc);
}

using namespace std;

bool operator==(const struct hook &a, const struct hook &b){
    return memcmp(&a, &b, sizeof(struct hook)) == 0;
}

#define NOT_EQUAL_RETURN_COND(A, B)  do {if (A != B) { return A < B;}} while (0)

/*
 * The set wants to know if our elements are the same. We only want
 * this to happen in the case that our structs are actual duplicates.
 * Otherwise we want them ordered by address and then asid and so on.
 */
bool operator<(const struct hook &a, const struct hook &b){
    return tie(a.addr, a.asid, a.type, a.cb.before_block_exec) < tie(b.addr, b.asid, b.type, b.cb.before_block_exec);//, b.km, b.enabled);
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
SUPPORT_CALLBACK_TYPE(start_block_exec)
SUPPORT_CALLBACK_TYPE(end_block_exec)

panda_cb before_block_translate_block_invalidator_callback;

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
    panda_enable_callback(self, PANDA_CB_START_BLOCK_EXEC, start_block_exec_callback);
    panda_enable_callback(self, PANDA_CB_END_BLOCK_EXEC, end_block_exec_callback);
}

void disable_hooking() {
    assert(self != NULL);
    panda_disable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, before_tcg_codegen_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_callback);
    panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, after_block_translate_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, before_block_exec_callback);
    panda_disable_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, after_block_exec_callback);
    panda_disable_callback(self, PANDA_CB_START_BLOCK_EXEC, start_block_exec_callback);
    panda_disable_callback(self, PANDA_CB_END_BLOCK_EXEC, end_block_exec_callback);
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
    pair<hooks_panda_cb, panda_cb_type> p (h->cb, h->type);
    struct hook_symbol_resolve sh;
    sh.enabled = true;
    sh.cb = handle_hook_return;
    symbols_to_handle.push_back(p);
    sh.id = symbols_to_handle.size() - 1;
    sh.hook_offset = h->offset;
    if (h->hook_offset){
        sh.offset = h->offset;
        memset((void*) &sh.name, 0, sizeof(sh.name));
    }else{
        memcpy((void*) &sh.name, (void*) &h->name, sizeof(sh.name));
    }
    memcpy((void*) &sh.section,(void*) &h->section, sizeof(sh.section));
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

#define ADD_CALLBACK_TYPE(TYPE, TYPE_UPPER) \
    case PANDA_CB_ ## TYPE_UPPER: \
        temp_## TYPE ## _hooks.push_back(*h); \
        panda_enable_callback(self, PANDA_CB_ ## TYPE_UPPER , TYPE ## _callback); \
        break;

bool first_tb_chaining = false;
set<target_ulong> pcs_to_flush;

void hooks_flush_pc(target_ulong pc){
    pcs_to_flush.insert(pc);
    panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_block_invalidator_callback);
}

void before_block_translate_invalidator(CPUState* cpu, target_ulong pc_val){
    assert(cpu != (CPUState*)NULL && "Cannot register TCG-based hooks before guest is created. Try this in after_machine_init CB");
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    target_ulong pc, cs_base;
    uint32_t flags;
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    set<target_ulong>::iterator it = pcs_to_flush.begin();
    while (it != pcs_to_flush.end()){
        target_ulong pc_target = *it;
        uint32_t h = tb_jmp_cache_hash_func(pc_target);
        TranslationBlock *tb = atomic_read(&cpu->tb_jmp_cache[h]);
        if (unlikely(tb && tb->pc == pc_target && tb->cs_base == cs_base)){
            tb_phys_invalidate(tb, tb->page_addr[0]);
            atomic_set(&cpu->tb_jmp_cache[h], NULL);
            it = pcs_to_flush.erase(it);
            continue;
        }
        ++it;
    }
    if (pcs_to_flush.empty())
        panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_block_invalidator_callback);
}

void add_hook(struct hook* h) {
    if (h->type != PANDA_CB_BEFORE_TCG_CODEGEN && !first_tb_chaining){
        // if we ever register a non tcg_codegen we must disable tb chaining
        panda_disable_tb_chaining();
        first_tb_chaining = true;
    }
    if (h->type == PANDA_CB_BEFORE_TCG_CODEGEN){
        hooks_flush_pc(h->addr);
    }
    switch (h->type){
        ADD_CALLBACK_TYPE(before_tcg_codegen, BEFORE_TCG_CODEGEN)
        ADD_CALLBACK_TYPE(before_block_translate, BEFORE_BLOCK_TRANSLATE)
        ADD_CALLBACK_TYPE(after_block_translate, AFTER_BLOCK_TRANSLATE)
        ADD_CALLBACK_TYPE(before_block_exec_invalidate_opt, BEFORE_BLOCK_EXEC_INVALIDATE_OPT)
        ADD_CALLBACK_TYPE(before_block_exec, BEFORE_BLOCK_EXEC)
        ADD_CALLBACK_TYPE(after_block_exec, AFTER_BLOCK_EXEC)
        ADD_CALLBACK_TYPE(start_block_exec, START_BLOCK_EXEC)
        ADD_CALLBACK_TYPE(end_block_exec, END_BLOCK_EXEC)
        default:
            printf("couldn't find hook type. Invalid %d\n", (int) h->type);
    }
}

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
    target_ulong asid = panda_current_asid(cpu); \
    bool in_kernel = panda_in_kernel(cpu); \
    struct hook hook_container; \
    memset(&hook_container, 0, sizeof(hook_container)); \
    hook_container.addr = PC; \
    set<struct hook>::iterator it;

#define LOOP_ASID_CHECK(NAME, EXPR, COMPARATOR_TO_BLOCK)\
    hook_container.asid = asid; \
    it = NAME ## _hooks[asid].lower_bound(hook_container); \
    while(it != NAME ## _hooks[asid].end() && it->addr COMPARATOR_TO_BLOCK){ \
        auto h = (hook*)&(*it); \
        if (likely(h->enabled)){ \
            if (h->asid == asid){ \
                if (h->km == MODE_ANY || (in_kernel && h->km == MODE_KERNEL_ONLY) || (!in_kernel && h->km == MODE_USER_ONLY)){ \
                    EXPR \
                    if (!h->enabled){ \
                        it = NAME ## _hooks[asid].erase(it); \
                        continue; \
                    } \
                    /*memcpy((void*)&(*it), (void*)&h, sizeof(struct hook));*/ \
                } \
            } \
        }\
        ++it; \
    }

#define HOOK_GENERIC_RET_EXPR(EXPR, UPPER_CB_NAME, NAME, VALUE, COMPARATOR_TO_BLOCK, PC) \
    MAKE_HOOK_FN_START(UPPER_CB_NAME, NAME, VALUE, PC) \
    LOOP_ASID_CHECK(NAME, EXPR, COMPARATOR_TO_BLOCK) \
    if (asid != 0){ \
        asid = 0; \
        LOOP_ASID_CHECK(NAME, EXPR, COMPARATOR_TO_BLOCK) \
    }


#define MAKE_HOOK_VOID(UPPER_CB_NAME, NAME, PASSED_ARGS, PC, ...) \
void cb_ ## NAME ## _callback PASSED_ARGS { \
    /*printf("VOID calling %llx guest_pc %llx\n", (long long unsigned int) panda_current_pc(cpu), (long long unsigned int)cpu->panda_guest_pc);*/\
    HOOK_GENERIC_RET_EXPR( (*(h->cb.NAME))(__VA_ARGS__);, UPPER_CB_NAME, NAME, , == hook_container.addr, PC) \
}

// first level hook that goes to other hooks?

#define MAKE_HOOK_BOOL(UPPER_CB_NAME, NAME, PASSED_ARGS, PC, ...) \
bool cb_ ## NAME ## _callback PASSED_ARGS { \
    bool ret = false; \
    HOOK_GENERIC_RET_EXPR(ret |= (*(h->cb.NAME))(__VA_ARGS__);, UPPER_CB_NAME, NAME, false, == hook_container.addr, PC) \
    return ret; \
}
    
void cb_tcg_codegen_middle_filter(CPUState* cpu, TranslationBlock *tb) {
    HOOK_GENERIC_RET_EXPR(/*printf("TCG calling %llx from %llx with hook %llx guest_pc %llx\n", (long long unsigned int) panda_current_pc(cpu), (long long unsigned int)tb->pc, (long long unsigned int)h->addr, (long long unsigned int)cpu->panda_guest_pc); printf("made it to hook %p\n", (void*)h->cb.before_block_exec);*/ (*(h->cb.before_tcg_codegen))(cpu, tb, h);, BEFORE_TCG_CODEGEN, before_tcg_codegen, , < tb->pc + tb->size, tb->pc );
}

void cb_before_tcg_codegen_callback (CPUState* cpu, TranslationBlock *tb) {
    if (unlikely(! temp_before_tcg_codegen_hooks.empty())){
        for (auto &h: temp_before_tcg_codegen_hooks) {
            before_tcg_codegen_hooks[h.asid].insert(h);
        }
        temp_before_tcg_codegen_hooks.clear();
    }
    if (unlikely(before_tcg_codegen_hooks.empty())){
        panda_disable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, before_tcg_codegen_callback);
    }
    bool in_kernel = panda_in_kernel(cpu);
    struct hook hook_container;
    set<target_ulong> inserted_addresses;
    memset(&hook_container, 0, sizeof(hook_container));
    hook_container.addr = tb->pc;
    TCGOp *first_instr = NULL;
    for (auto& a : before_tcg_codegen_hooks){
        target_ulong asid = a.first;
        set<struct hook>::iterator it;
        hook_container.asid = asid;
        it = before_tcg_codegen_hooks[asid].lower_bound(hook_container); 
        while(it != before_tcg_codegen_hooks[asid].end() && it->addr < tb->pc + tb->size){
            auto h = (hook*)&(*it);
            if (likely(h->enabled)){
                if (h->asid == asid){ 
                    if (h->km == MODE_ANY || (in_kernel && h->km == MODE_KERNEL_ONLY) || (!in_kernel && h->km == MODE_USER_ONLY)){
                        auto exclude = inserted_addresses.find(h->addr);
                        if (exclude == inserted_addresses.end()){
                            TCGOp* op = NULL;
                            if (h->addr == tb->pc){
                                if (!first_instr) {
                                    first_instr = find_first_guest_insn();
                                }
                                op = first_instr;
                            }else{
                                op = find_guest_insn_by_addr(h->addr);
                            }
                            if (op != NULL){
                                insert_call(&op, cb_tcg_codegen_middle_filter, cpu, tb);
                                inserted_addresses.insert(h->addr);
                            }
                        } 
                    }
                } 
            }else{
                printf("erasing hook\n");
                it = before_tcg_codegen_hooks[asid].erase(it);
                continue;
            }
            ++it;
        }
    }
}


MAKE_HOOK_VOID(BEFORE_BLOCK_TRANSLATE, before_block_translate, (CPUState *cpu, target_ulong pc), panda_current_pc(cpu), cpu, pc, h)

MAKE_HOOK_VOID(AFTER_BLOCK_TRANSLATE, after_block_translate, (CPUState *cpu, TranslationBlock *tb), tb->pc, cpu, tb, h)

MAKE_HOOK_BOOL(BEFORE_BLOCK_EXEC_INVALIDATE_OPT, before_block_exec_invalidate_opt, (CPUState* cpu, TranslationBlock* tb), tb->pc, cpu, tb, h)

MAKE_HOOK_VOID(BEFORE_BLOCK_EXEC, before_block_exec, (CPUState *cpu, TranslationBlock *tb), tb->pc, cpu, tb, h)

MAKE_HOOK_VOID(AFTER_BLOCK_EXEC, after_block_exec, (CPUState *cpu, TranslationBlock *tb, uint8_t exitCode), tb->pc, cpu, tb, exitCode, h)

MAKE_HOOK_VOID(START_BLOCK_EXEC, start_block_exec, (CPUState *cpu, TranslationBlock *tb), tb->pc, cpu, tb, h)

MAKE_HOOK_VOID(END_BLOCK_EXEC, end_block_exec, (CPUState *cpu, TranslationBlock *tb), tb->pc, cpu, tb, h)

void erase_asid(target_ulong asid){
    before_tcg_codegen_hooks.erase(asid);
    before_block_translate_hooks.erase(asid);
    after_block_translate_hooks.erase(asid);
    before_block_exec_invalidate_opt_hooks.erase(asid);
    before_block_exec_hooks.erase(asid);
    after_block_exec_hooks.erase(asid);
    start_block_exec_hooks.erase(asid);
    end_block_exec_hooks.erase(asid);
}

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
    REGISTER_AND_DISABLE_CALLBACK(_self, start_block_exec, START_BLOCK_EXEC)
    REGISTER_AND_DISABLE_CALLBACK(_self, end_block_exec, END_BLOCK_EXEC)
    
    before_block_translate_block_invalidator_callback.before_block_translate = before_block_translate_invalidator; 
    panda_register_callback(_self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_block_invalidator_callback);
    panda_disable_callback(_self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, before_block_translate_block_invalidator_callback);
    return true;
}

void uninit_plugin(void *self) {
    // if we don't clear tb's when this exits we have TBs which can call
    // into our exited plugin.
    panda_do_flush_tb();
    disable_hooking();
}
