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
 * PANDAENDCOMMENT */

#include "panda/plugin.h"
#include "panda/checkpoint.h"

bool init_plugin(void *);
void uninit_plugin(void *);

bool before_block_exec(CPUState *env, TranslationBlock *tb);

bool before_block_exec(CPUState *env, TranslationBlock *tb) {
    static int progress = 0;
    static void *saved = NULL;
    static void *last = NULL;
    if (rr_get_guest_instr_count() / 50000 > progress) {
        progress++;
        printf("Taking panda checkpoint %u...\n", progress);
        last = panda_checkpoint();
        printf("Done.\n");
    }
    if (!saved && rr_get_guest_instr_count() > 100000) {
        printf("\n\nSaving checkpoint for restore!!\n\n");
        saved = last;
    }
    static int restart_count = 0;
    if (rr_get_guest_instr_count() > 200000 && restart_count < 3) {
        restart_count++;
        printf("Restarting...\n");
        panda_restart(saved);
        printf("Done.\n");
        return true;
    }
    return false;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec_invalidate_opt = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

    return true;
}

void uninit_plugin(void *self) { }
