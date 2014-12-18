/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "config.h"
#include "qemu-common.h"

#include "panda_plugin.h"
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    int i;

    OsiProc *current = get_current_process(env);
    printf("Current process: %s, PID %04x PPID %04x\n", current->name, current->pid, current->ppid);
    OsiProcs *ps;
    ps = get_processes(env);
    if (ps == NULL) {
        printf("Process list not available.\n");
    }
    else {
        printf("Process list (%d procs):\n", ps->num);
        for (i = 0; i < ps->num; i++)
            printf("  %-16s %04x %04x\n", ps->proc[i].name, ps->proc[i].pid, ps->proc[i].ppid);
    }
    OsiModules *ms;
    ms = get_libraries(env, current);
    if (ms == NULL) {
        printf("DLL list is paged out.\n");
    }
    else {
        printf("DLL list (%d libs):\n", ms->num);
        for (i = 0; i < ms->num; i++)
            printf("  %08x %08x %s %s\n", ms->module[i].base, ms->module[i].size, ms->module[i].name, ms->module[i].file);
    }
    
    // Cleanup
    free_osiproc(current);
    free_osiprocs(ps);
    free_osimodules(ms);

    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    if(!init_osi_api()) return false;

    return true;
}

void uninit_plugin(void *self) { }
