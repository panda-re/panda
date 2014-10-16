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

extern "C" {

#include "config.h"
#include "qemu-common.h"

#include "panda_plugin.h"

#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

}

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);

}

static target_ulong blockpc = 0;

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    target_ulong callers[64];
    if (tb->pc == blockpc) {
        printf("Func stack @ 0x" TARGET_FMT_lx ": ", blockpc);
        int n = get_functions(callers, 64, env);
        for (int i = n - 1; i >= 0; i--) {
            printf(TARGET_FMT_lx " ", callers[i]);
        }
        printf("\n");
    }

    return 0;
}

bool init_plugin(void *self) {
    init_callstack_instr_api();

    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("printstack");
    blockpc = panda_parse_ulong(args, "pc", 0);
    if (blockpc == 0) return false;

    return true;
}

void uninit_plugin(void *self) { }
