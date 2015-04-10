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

#include "panda_common.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

#include "pandalog.h"
#include "panda/panda_addr.h"

}

#include <map>
#include <set>

#include "../taint2/taint2.h"
#include "../taint2/taint2_ext.h"

// NB: callstack_instr_ext needs this, sadly
#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
void taint_change(void);

}

target_ulong last_asid = 0;

void taint_change(Addr a) {
    if (taint2_query(a)) {
        extern CPUState *cpu_single_env;
        CPUState *env = cpu_single_env;
        target_ulong asid = panda_current_asid(env);
        if (asid != last_asid) {
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.has_asid = 1;
            ple.asid = asid;
            pandalog_write_entry(&ple);           
            last_asid = asid;
        }
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.tainted_instr = true;
        pandalog_write_entry(&ple);
        taint2_query_pandalog(a);    
        callstack_pandalog();
    }
}

bool init_plugin(void *self) {
    panda_require("taint2");
    assert(init_taint2_api());
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    PPP_REG_CB("taint2", on_taint_change, taint_change);
    taint2_track_taint_state();
    return true;
}

void uninit_plugin(void *self) {
}
