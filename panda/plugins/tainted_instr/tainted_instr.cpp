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
#include <stdint.h>    
}

#include "panda/plugin.h"

#include "taint2/taint2.h"

extern "C" {
#include "taint2/taint2_ext.h"
}

// NB: callstack_instr_ext needs this, sadly
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include <map>
#include <set>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
void taint_change(void);

}


bool summary = false;
uint64_t num_tainted_instr = 0;
uint64_t num_tainted_instr_observed = 0;
bool replay_ended = false;

#include <map>
#include <set>

// map from asid -> pc
std::map<uint64_t,std::set<uint64_t>> tainted_instr;

target_ulong last_asid = 0;
target_ulong last_pc = 0;

void taint_change(Addr a, uint64_t size) {
    if (replay_ended) return;
    if (!replay_ended 
        && num_tainted_instr != 0 
        && (num_tainted_instr_observed == num_tainted_instr)) {
        // analysis complete
        printf ("tainted_instr ending early -- seen enough\n");
        panda_end_replay();
        replay_ended = true;
        return;
    }
    CPUState *env = first_cpu; // cpu_single_env;
    target_ulong asid = panda_current_asid(env);
    target_ulong pc = panda_current_pc(env);
    uint32_t num_tainted = 0;
    for (uint32_t i=0; i<size; i++) {
        a.off = i;
        num_tainted += (taint2_query(a) != 0);
    }
    if (num_tainted > 0) {            
        if (summary) {
            tainted_instr[asid].insert(pc);
        }
        else {
            if (pandalog) {
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
                if (pandalog) {
                    pandalog_write_entry(&ple);
                }
                pandalog_callstack_free(ti->call_stack);
                for (uint32_t i=0; i<num_tainted; i++) {
                    pandalog_taint_query_free(ti->taint_query[i]);
                }
                free(ti);
            }
            else {
                printf ("  pc = 0x%" PRIx64 "\n", (uint64_t) pc);
            }
        }
        if (asid != last_asid) {
            if (pandalog) {
                Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                ple.has_asid = 1;
                ple.asid = asid;
                if (pandalog) {
                    pandalog_write_entry(&ple);
                }
            }
            num_tainted_instr_observed++;
        }
        else if (pc != last_pc) {
            num_tainted_instr_observed++;
            if (0 == (num_tainted_instr_observed % 1000))
                printf ("%" PRId64 " tainted instr observed\n", num_tainted_instr_observed);
        }
    }
    last_asid = asid;
    last_pc = pc;
}

bool init_plugin(void *self) {
    panda_require("taint2");
    assert(init_taint2_api());
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_arg_list *args = panda_get_args("tainted_instr");
    summary = panda_parse_bool_opt(args, "summary", "summary tainted instruction info");
    num_tainted_instr = panda_parse_uint64_opt(args, "num", 0, "number of tainted instructions to log or summarize");
    if (summary) printf ("tainted_instr summary mode\n");
    else printf ("tainted_instr full mode\n");
    PPP_REG_CB("taint2", on_taint_change, taint_change);
    // this tells taint system to enable extra instrumentation
    // so it can tell when the taint state changes
    taint2_track_taint_state();
    return true;
}

void uninit_plugin(void *self) {
    if (summary) {
        Panda__TaintedInstrSummary *tis = (Panda__TaintedInstrSummary *) malloc (sizeof (Panda__TaintedInstrSummary));
        for (auto kvp : tainted_instr) {
            uint64_t asid = kvp.first;
            if (!pandalog) 
                printf ("tainted_instr: asid=0x%" PRIx64 "\n", asid);
            for (auto pc : kvp.second) {
                if (pandalog) {
                    *tis = PANDA__TAINTED_INSTR_SUMMARY__INIT;
                    tis->asid = asid;
                    tis->pc = pc;
                    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                    ple.tainted_instr_summary = tis;
                    pandalog_write_entry(&ple);
                }
                else {
                    printf ("  pc=0x%" PRIx64 "\n", (uint64_t) pc);
                }
            }
        }
        free(tis);
    }
}
