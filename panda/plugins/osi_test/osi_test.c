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

// Specify when the OSI test code is called.
//    OSI_TEST_ON_ASID_CHANGED defined -> on context switches
//    OSI_TEST_ON_ASID_CHANGED undefined -> for each executed block
#define OSI_TEST_ON_ASID_CHANGED

#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int asid_changed(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd);
int before_block_exec(CPUState *cpu, TranslationBlock *tb);
int after_block_exec(CPUState *cpu, TranslationBlock *tb, uint8_t exitCode);

int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    OsiProc *current = get_current_process(cpu);
    if(current) {
        printf("Current process: %s PID:" TARGET_FMT_ld " PPID:" TARGET_FMT_ld "\n", current->pid > 0 ? current->name : "N/A", current->pid, current->ppid);
    } else {
        printf("Cannot get current process details.\n");
    }
    
    printf("\n");

    GArray *ps = get_processes(cpu);
    if (ps == NULL) {
        printf("Process list not available.\n");
    } else {
        printf("Process list (%d procs):\n", ps->len);
        for (int i = 0; i < ps->len; i++) {
            OsiProc *p = &g_array_index(ps, OsiProc, i);
            printf("  %-16s\t" TARGET_FMT_ld "\t" TARGET_FMT_ld "\n", p->name, p->pid, p->ppid);
        }
    }

    printf("\n-------------------------------------------------\n\n");

    // Cleanup
    free_osiproc(current);
    g_array_free(ps, true);

    return 0;
}

int after_block_exec(CPUState *cpu, TranslationBlock *tb, uint8_t exitCode) {
    OsiProc *current = get_current_process(cpu);
    GArray *ms = get_libraries(cpu, current);
    if (ms == NULL) {
        printf("No mapped dynamic libraries.\n");
    } else {
        printf("Dynamic libraries list (%d libs):\n", ms->len);
        for (int i = 0; i < ms->len; i++) {
            OsiModule *m = &g_array_index(ms, OsiModule, i);
            printf("\t0x" TARGET_FMT_lx "\t" TARGET_FMT_ld "\t%-24s %s\n", m->base, m->size, m->name, m->file);
        }
    }

    printf("\n");

    GArray *kms = get_modules(cpu);
    if (kms == NULL) {
        printf("No mapped kernel modules.\n");
    } else {
        printf("Kernel module list (%d modules):\n", kms->len);
        for (int i = 0; i < kms->len; i++) {
            OsiModule *km = &g_array_index(kms, OsiModule, i);
            printf("\t0x" TARGET_FMT_lx "\t" TARGET_FMT_ld "\t%-24s %s\n", km->base, km->size, km->name, km->file);
        }
    }

    printf("\n-------------------------------------------------\n\n");

    // Cleanup
    free_osiproc(current);
    g_array_free(ms, true);
    g_array_free(kms, true);

    return 0;
}

int asid_changed(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd) {
    // tb argument is not used by before_block_exec()
    before_block_exec(cpu, NULL);
    after_block_exec(cpu, NULL, TB_EXIT_IDX0);
    return 0;
}

bool init_plugin(void *self) {
#if defined(OSI_TEST_ON_ASID_CHANGED)
    // relatively short execution
    // loaded library information will be for the previously running process
    panda_cb pcb = { .asid_changed = asid_changed };
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
#else
    // expect this to take forever to run
    // prints loaded library information after the basic block executes
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    panda_cb pcb2 = { .after_block_exec = after_block_exec };
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb2);
#endif

    panda_require("osi");
    if(!init_osi_api()) return false;

    return true;
}

void uninit_plugin(void *self) { }
