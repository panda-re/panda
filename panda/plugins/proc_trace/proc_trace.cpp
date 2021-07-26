/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano          fasano@mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/plog.h"

extern "C" {
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi/os_intro.h"


#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

// count for non-replay
uint64_t instr_count = 0;

// returns an instr count
// either using rr (if we are in replay)
// or by computing it if we are live
uint64_t get_instr_count() {
    if (rr_in_replay())
        return rr_get_guest_instr_count();
    else
        return instr_count;
}

// TODO enable this callback on init if not replay!
void bbe(CPUState *env, TranslationBlock *tb) {
    if (!rr_in_replay()) {
        instr_count += tb->icount; // num instr in this block
    }
}

void task_changed(CPUState *cpu) {
    OsiProc *proc = get_current_process(cpu);
    OsiThread *thread = get_current_thread(cpu);

    if (proc == NULL || thread == NULL) {
        printf("Warning NULL task or process returned from OSI\n");
        return;
    }

    Panda__ProcTrace *pt = (Panda__ProcTrace *) malloc(sizeof(Panda__ProcTrace));
    assert(pt != NULL && "Failed to allocate ProcTrace object");
    *pt = PANDA__PROC_TRACE__INIT;

    pt->pid =  proc->pid;
    pt->create_time = proc->create_time;
    pt->ppid = proc->ppid;
    pt->name = strdup(proc->name);
    pt->tid = thread->tid;
    pt->start_instr = get_instr_count();

    //pt->has_count = 1;
    //pt->count = pd.count;

    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.proc_trace = pt;
    pandalog_write_entry(&ple);
    free(pt);
    free_osithread(thread);
    free_osiproc(proc);
}


bool init_plugin(void *self) {
    if (!pandalog) {
        fprintf(stderr, "ERROR: proc_trace can only be used when a pandalog is specified\n");
        return false;
    }
    panda_require("osi");
    assert(init_osi_api());
    PPP_REG_CB("osi", on_task_change, task_changed);
    return true;
}

void uninit_plugin(void *self) { }
