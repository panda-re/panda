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
#include "rr_log.h"

#include "panda_plugin.h"

#include <stdio.h>

extern RR_log *rr_nondet_log;

static double percent = 0.0;

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (rr_get_percentage() > percent) {
        printf("Saving memory to initial.raw.\n");
        panda_memsavep(fopen("initial.raw", "wb"));
        rr_do_end_replay(0);
    }
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("memsavep");
    percent = panda_parse_double(args, "percent", 0.0);

    return true;
}

void uninit_plugin(void *self) {

}
