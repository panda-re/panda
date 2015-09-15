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

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_common.h"
#include "pandalog.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

#include "rr_log.h"
#include "panda_plugin_plugin.h"
#include "guestarch.h"

#include <string.h>
}

// NB: callstack_instr_ext needs this, sadly
#include "../common/prog_point.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include <set>

const char *process_name;
target_ulong process_asid=0;
std::set<uint64_t> process_bb;
uint64_t process_total_bb=0;

int coverage_before_block_exec(CPUState *env, TranslationBlock *tb) {
#ifdef CONFIG_SOFTMMU
    OsiProc *p = get_current_process(env);
    uint64_t asid = panda_current_asid(env);    
    if (process_asid == 0) {
        // look for process matching the one we want
        if (p) {
            if (strcmp(process_name, p->name) == 0) {
                process_asid = asid;
                printf ("coverage plugin: saw cr3=0x%" PRIx64 " for process=[%s]\n",
                        asid, process_name);
            }
        }
    }
    if (process_asid !=0 && process_asid == asid) {
        // collect bb for this asid
        process_bb.insert(tb->pc);
        // and count number of bb executed (regardless of repetetion)
        process_total_bb ++;
    }
        
#endif
    return 0;
}

bool init_plugin(void *self) {

    printf ("Initializing plugin coverage\n");
    panda_arg_list *args = panda_get_args("coverage");
    process_name = panda_parse_string(args, "process", "");
    panda_require("osi");
    // this sets up OS introspection API
    assert(init_osi_api());
    panda_cb pcb;    
    pcb.before_block_exec = coverage_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    return true;
}

void uninit_plugin(void *self) {
    printf ("coverage plugin: total sequential bb for process = %" PRIu64 "\n", process_total_bb);
    printf ("coverage plugin: total unique bb for process = %d\n", (int) (process_bb.size()));
    for ( auto pc : process_bb ) {
        printf ("coverage plugin:   bb 0x%" PRIx64 "\n", pc);
    }

}
