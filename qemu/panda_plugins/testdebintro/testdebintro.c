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
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"

#include "panda_plugin.h"
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);
int monitor_callback(Monitor *mon, const char *cmd);

bool get_pid = false;

// Monitor callback. This gets a string that you can then parse for
// commands. Could do something more complex here, e.g. getopt.
int monitor_callback(Monitor *mon, const char *cmd) {
#ifdef CONFIG_SOFTMMU
    char *cmd_work = g_strdup(cmd);
    char *word;
    word = strtok(cmd_work, " ");
    do {
        if (strncmp("pid", word, 3) == 0) {
            get_pid = true;
        }
    } while((word = strtok(NULL, " ")) != NULL);
    g_free(cmd_work);
#endif
    return 1;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (get_pid) {
        int i;

        printf("=====================================================\n");
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
        
        // Cleanup
        free_osiproc(current);
        free_osiprocs(ps);
        get_pid = false;
    }
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb;
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.monitor = monitor_callback;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    if(!init_osi_api()) return false;

    return true;
}

void uninit_plugin(void *self) { }
