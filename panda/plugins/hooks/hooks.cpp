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
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
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
// Mapping of addresses to hook functions
vector<struct hook> hooks;

// Callback object
panda_cb c_callback;

// Handle to self
void* self = NULL;

bool disable_osi;

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

OsiModule* get_current_module(CPUState* cpu, target_ulong pc){
   OsiProc* current = get_current_process(cpu);
   GArray *ms = get_mappings(cpu, current);
    for (int i = 0; i < ms->len; i++) { 
        OsiModule *m = &g_array_index(ms, OsiModule, i); 
        if (m->base <= pc && pc <= m->base + m->size){
            return m;
        }
    }
    return (OsiModule*) NULL;
}

OsiModule* get_base_overall_library(CPUState* cpu, char* name){
   OsiProc* current = get_current_process(cpu);
   GArray *ms = get_mappings(cpu, current);
    for (int i = 0; i < ms->len; i++) { 
        OsiModule *m = &g_array_index(ms, OsiModule, i); 
        // check that the name matches
        if (strncmp(m->name, name, MAX_PROCNAME_LENGTH) == 0){
            char elfhdr[4];
            // look for an elf header
            if (panda_virtual_memory_read(cpu,m->base, (uint8_t*) elfhdr, 4) == MEMTX_OK){
                if (elfhdr[0] == '\x7f' && elfhdr[1] == 'E' && elfhdr[2] == 'L' && elfhdr[3] == 'F'){
                    return m;
                }
            }
        }
    }
    return (OsiModule*) NULL;
}


// The panda callback to determine if we should call a python callback
bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb) {
    // Call any callbacks registered at this PC. 
    // Any called callback may invalidate the translation block
    bool ret = false;
    target_ulong asid = panda_current_asid(cpu);
    OsiProc *current = NULL;
    OsiModule *current_module = NULL;

    for (auto& hook: hooks){
        if (hook.enabled){
            if (hook.asid == 0 || hook.asid == asid){
                bool filter_procname = hook.procname[0] != 0;
                bool filter_libname = hook.libname[0] != 0;
                /* 
                * we only ever ask for OsiProc or OsiModule to be filled 
                * if a process actually uses it. We then cache it.
                */
                if (filter_procname && current == NULL && !disable_osi){
                    current = get_current_process(cpu);
                }
                if (filter_libname && current_module == NULL && !disable_osi){
                    /**
                     * If we have 4 memory regions for libc we first need to
                     * determine which is the "start module". In libraries
                     * this is the one that has an ELF header at its start.
                     */
                    OsiModule* local_module = get_current_module(cpu, tb->pc);
                    if (local_module->name != NULL)
                        current_module = get_base_overall_library(cpu, local_module->name);
                }

                if (disable_osi){ 
                    // we're not doing osi stuff
                    // we don't support any of these options and will pass
                    // on hooks that support them.
                    if (!(filter_procname || filter_libname || hook.is_address_library_offset)){
                        if (hook.start_addr <= tb->pc && tb->pc <= hook.end_addr){
                            ret |= (*(hook.cb))(cpu, tb, &hook);
                        }
                    }
                }else { // doing osi stuff
                    if (!filter_procname || (current->name != NULL && strncmp(current->name, hook.procname, MAX_PROCNAME_LENGTH) == 0)){
                        if (!filter_libname || (current_module->name != NULL && strncmp(current_module->name, hook.libname, MAX_PROCNAME_LENGTH) == 0)){
                            /*
                            ** We offer two addressing modes: absolute and
                            ** offset into libraries.
                            */
                            if (hook.is_address_library_offset){
                                if (hook.start_addr + current_module->base <= tb->pc && tb->pc <= current_module->base + hook.end_addr){
                                    ret |= (*(hook.cb))(cpu, tb, &hook);
                                }           
                            }else{
                                if (hook.start_addr <= tb->pc && tb->pc <= hook.end_addr){
                                    ret |= (*(hook.cb))(cpu, tb, &hook);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return ret;
}


bool init_plugin(void *_self) {
    // On init, register a callback but don't enable it
    self = _self;
    panda_arg_list *args = panda_get_args("hooks");
    disable_osi = panda_parse_bool_opt(args, "disable_osi", "disable osi process name options");

    panda_disable_tb_chaining();

    c_callback.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);

    if (!disable_osi){
        panda_require("osi");
        assert(init_osi_api());
    }

    return true;
}

void uninit_plugin(void *self) {}
