#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
}


#include<map>
#include<vector>
#include<set>
#include<iostream>
using namespace std;

typedef target_ulong Asid;

void cleanup_osi(OsiProc *current, OsiThread *thread, GArray *ms) {
    if (current) free_osiproc(current);
    if (thread) free_osithread(thread);
    if (ms) cleanup_garray(ms);
}

const char* program_name;

uint64_t get_libs_count = 0;
uint64_t get_libs_failed_count = 0;

void get_libs(CPUState *env) {

    get_libs_count ++;

    bool fail = false;
    OsiProc *current =  get_current_process(env);
    if (current == NULL) fail=true;
	if (program_name && strcmp(current->name, program_name)) fail=true;
    if (current->pid == 0) fail=true;
    GArray *ms = get_mappings(env, current);
    if (ms == NULL) fail=true;
    OsiThread *thread = get_current_thread(env);
    if (thread == NULL) fail=true;

    assert (pandalog);

    if (fail) {
        get_libs_failed_count ++;
    }
    else {

        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        Panda__LoadedLibs ll = PANDA__LOADED_LIBS__INIT;
        Panda__Module** m = (Panda__Module **) malloc (sizeof (Panda__Module *) * ms->len);
        for (int i = 0; i < ms->len; i++) {
            OsiModule *module = &g_array_index(ms, OsiModule, i);
            m[i] = (Panda__Module *) malloc (sizeof (Panda__Module));
            *(m[i]) = PANDA__MODULE__INIT;
            if (module->name == 0x0)
              m[i]->file = strdup("none");
            else
              m[i]->name = strdup(module->name);

            if (module->file == 0x0)
                m[i]->file = strdup("none");
            else
                m[i]->file = strdup(module->file);
            m[i]->base_addr = module->base;
            m[i]->size = module->size;
        }
        ll.modules = m;
        ll.n_modules = ms->len;
        ll.has_pid = true;
        ll.has_ppid = true;
        ll.has_create_time = true;
        ll.has_tid = true;
        ll.proc_name = strdup(current->name);
        ll.pid = current->pid;
        ll.ppid = current->ppid;
        ll.create_time = current->create_time;
        ll.tid = thread->tid;

        Asid asid = panda_current_asid(env);

        ple.has_asid = true;
        ple.asid = asid;
        ple.asid_libraries = &ll;
        pandalog_write_entry(&ple);

        for (int i=0; i<ms->len; i++) {
            free(m[i]->name);
            free(m[i]->file);
        }
        free(m);
    }

    cleanup_osi(current, thread, ms);
}



// 9 long sys_mmap(

void mmap_return(CPUState *cpu, target_ulong pc, unsigned long addr, unsigned long length, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long offset) {
    get_libs(cpu);
}


uint64_t bb_count = 0;

void before_block(CPUState *env, TranslationBlock *tb) {

    // check up on module list every 50 bb
    bb_count ++;
    if ((bb_count % 100) == 0) {
        get_libs(env);
    }

}


bool init_plugin(void *self) {
    panda_require("osi"); 
    assert(init_osi_api());
    panda_require("syscalls2");

    #ifdef TARGET_X86_64
    PPP_REG_CB("syscalls2", on_sys_mmap_return, mmap_return);
    #else
    /* #error "No on_sys_mmap_return for target" */
    #endif

    panda_cb pcb;
    pcb.before_block_exec = before_block;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args;
    args = panda_get_args("loaded_libs");
    program_name = panda_parse_string_opt(args, "program_name", NULL, "program name to collect libraries for");

    return true;
}

void uninit_plugin(void *self) {

    cout << "get_libs_count = " << get_libs_count << "\n";
    cout << "get_libs_failed_count = " << get_libs_failed_count << "\n";
    cout << "frac = " << ((float) get_libs_failed_count) / get_libs_count << "\n";

}
