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
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
#include "console.h"

#include "panda_plugin.h"
#include "rr_log_all.h"

#include <stdio.h>
#include <stdlib.h>

int before_block_callback(CPUState *env, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

int num = 0;

int before_block_callback(CPUState *env, TranslationBlock *tb) {
    assert(rr_in_replay());
    char fname[256] = {0};
    static uint64_t total_insns = 0;
    if (total_insns == 0) total_insns = replay_get_total_num_instructions();
    if ((rr_prog_point.guest_instr_count / (double)total_insns) * 100 >= num) {
        snprintf(fname, 255, "replay_movie_%03d.ppm", (int)num);
        vga_hw_screen_dump(fname);
        num += 1;
    }
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    // In general you should always register your callbacks last, because
    // if you return false your plugin will be unloaded and there may be stale
    // pointers hanging around.
    pcb.before_block_exec = before_block_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    // Save the last frame
    char fname[256] = {0};
    snprintf(fname, 255, "replay_movie_%03d.ppm", (int)num);
    vga_hw_screen_dump(fname);
    printf("Unloading replaymovie plugin.\n");
}
