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
#include <stdint.h>
    
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

bool summary = false;

#include <map>
#include <set>

// map from asid -> pc
std::map<uint64_t,std::set<uint64_t>> tainted_instr;

target_ulong last_asid = 0;

void taint_change(Addr a, uint64_t size) {
    uint32_t num_tainted = 0;
    for (uint32_t i=0; i<size; i++) {
        a.off = i;
        num_tainted += (taint2_query(a) != 0);
    }
    if (num_tainted > 0) {            
        extern CPUState *cpu_single_env;
        CPUState *env = cpu_single_env;
        target_ulong asid = panda_current_asid(env);
        if (summary) {
            tainted_instr[asid].insert(panda_current_pc(env));
        }
        else {
            Panda__TaintedInstr *ti = (Panda__TaintedInstr *) malloc(sizeof(Panda__TaintedInstr));
            *ti = PANDA__TAINTED_INSTR__INIT;
            ti->call_stack = pandalog_callstack_create();
            ti->n_taint_query = num_tainted;
            ti->taint_query = (Panda__TaintQuery **) malloc (sizeof(Panda__TaintQuery *) * num_tainted);
            uint32_t j = 0;
            for (uint32_t i=0; i<size; i++) {
                a.off = i;
                if (taint2_query(a)) {
                    ti->taint_query[j++] = taint2_query_pandalog(a, 0);
                }
            }
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.tainted_instr = ti;
            pandalog_write_entry(&ple);
            pandalog_callstack_free(ti->call_stack);
            for (uint32_t i=0; i<num_tainted; i++) {
                pandalog_taint_query_free(ti->taint_query[i]);
            }
            free(ti);
        }
        if (asid != last_asid) {
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.has_asid = 1;
            ple.asid = asid;
            pandalog_write_entry(&ple);
            last_asid = asid;
        }
    }
}

bool init_plugin(void *self) {
    panda_require("taint2");
    assert(init_taint2_api());
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_arg_list *args = panda_get_args("tainted_instr");
    summary = panda_parse_bool(args, "summary");
    if (summary) printf ("tainted_instr summary mode\n"); else printf ("tainted_instr full mode\n");
    PPP_REG_CB("taint2", on_taint_change, taint_change);
    taint2_track_taint_state();
    return true;
}

void uninit_plugin(void *self) {
    if (summary) {
        Panda__TaintedInstrSummary *tis = (Panda__TaintedInstrSummary *) malloc (sizeof (Panda__TaintedInstrSummary));
        for (auto kvp : tainted_instr) {
            uint64_t asid = kvp.first;
            for (auto pc : kvp.second) {
                *tis = PANDA__TAINTED_INSTR_SUMMARY__INIT;
                tis->asid = asid;
                tis->pc = pc;
                Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                ple.tainted_instr_summary = tis;
                pandalog_write_entry(&ple);
            }
        }
        free(tis);
    }
}
