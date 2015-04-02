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

#include <stdio.h>
#include "../taint2/label_set.h"
#include "../taint2/taint2.h"
#include "panda/panda_addr.h"

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "../taint2/taint2_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"
#include "pandalog.h"
#include "panda_common.h"
#include "guestarch.h"
}


// NB: callstack_instr_ext needs this, sadly
#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

// this includes on_branch2_t
#include "../taint2/taint2.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU


bool first_enable_taint = true;


void tbranch_on_branch_taint2(Addr a) {
    if (taint2_query(a)) {
        // branch is tainted
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.has_tainted_branch = true;
        ple.tainted_branch = true;
        pandalog_write_entry(&ple);
        taint2_query_pandalog(a);
        callstack_pandalog();
    }
}


int tbranch_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
    if ((taint2_enabled()) && first_enable_taint) {
        first_enable_taint = false;
        PPP_REG_CB("taint2", on_branch2, tbranch_on_branch_taint2); 
        printf ("enabling on_branch taint api callbacks\n");
    }
    return 0;
}

#endif

bool init_plugin(void *self) {
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_require("taint2");
    assert (init_taint2_api());    
    panda_cb pcb;
    pcb.after_block_exec = tbranch_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    return true;
}

void uninit_plugin(void *self) {
}
