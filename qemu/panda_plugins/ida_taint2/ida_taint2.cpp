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

/*
 * Relies on taint2, osi, win7proc, and syscalls2.
 * PANDA args:
 *  -panda 'syscalls2:profile=windows7_x86;ida_taint2' -pandalog <plog_file>'
 *
 * If you know the name of your file and want to use the file_taint plugin, the
 * PANDA args become:
 *  -panda 'syscalls2:profile=windows7_x86;ida_taint2;file_taint:filename=<file>'
 *
 * Currently, very similar to tainted_instr
 *
 * XXX: Only tested for Windows 7 32-bit
 */

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
void taint_change(Addr, uint64_t);

}

target_ulong last_asid = 0;

void taint_change(Addr a, uint64_t size) {
    for (unsigned i = 0; i < size; i++){
        a.off = i;
        if (taint2_query(a)) {
            
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            /*
            ple.has_tainted_instr = true;
            ple.tainted_instr = true;
            pandalog_write_entry(&ple);
            */
            taint2_query_pandalog(a, i);
            ple = PANDA__LOG_ENTRY__INIT;
            ple.call_stack = pandalog_callstack_create();
            pandalog_write_entry(&ple);            
            pandalog_callstack_free(ple.call_stack);
        }
    }
}

bool init_plugin(void *self) {
    panda_require("taint2");
    assert(init_taint2_api());
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_require("win7proc");
    PPP_REG_CB("taint2", on_taint_change, taint_change);
    taint2_track_taint_state();
    return true;
}

void uninit_plugin(void *self) {}

