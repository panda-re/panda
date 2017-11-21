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

#include <cstdio>

#include "panda/addr.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "taint2/label_set.h"
#include "taint2/taint2.h"

extern "C" {
#include "panda/rr/rr_log.h"
#include "panda/plog.h"

#include "taint2/taint2_ext.h"
}

// NB: callstack_instr_ext needs this, sadly
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

// this includes on_branch2_t
#include "taint2/taint2.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

#include <stdint.h>
#include "tainted_branch_int_fns.h"

}



#ifdef CONFIG_SOFTMMU

bool summary = false;
bool liveness = false;

#include <map>
#include <set>

// map from asid -> pc
std::map<uint64_t,std::set<uint64_t>> tainted_branch;


// a taint label is just a uint32
typedef uint32_t Tlabel;

// liveness[pos] is # of branches byte pos in file was used to decide up to this point
std::map <Tlabel, uint64_t> liveness_map;

uint64_t get_liveness(Tlabel l) {
    return liveness_map[l];
}

// keep track of number of branches each label involved in
int taint_branch_aux(Tlabel ln, void *stuff) {
    liveness_map[ln] ++;
    return 0; // continue iter
}


void tbranch_on_branch_taint2(Addr a, uint64_t size) {
    if (pandalog) {
        // a is an llvm reg
        assert (a.typ == LADDR);
        // count number of tainted bytes on this reg
        uint32_t num_tainted = 0;
        Addr ao = a;
        for (uint32_t o=0; o<size; o++) {
            ao.off = o;
            num_tainted += (taint2_query(ao) != 0);
        }
        if (num_tainted > 0) {
            if (liveness) {
                // update liveness info for all input bytes from which lval derives
                for (uint32_t o=0; o<size; o++) {
                    ao.off = o;
                    taint2_labelset_addr_iter(a, taint_branch_aux, NULL);
                }        
            }
            if (summary) {
                CPUState *cpu = first_cpu;
                target_ulong asid = panda_current_asid(cpu);
                tainted_branch[asid].insert(panda_current_pc(cpu));
            }
            else {
                Panda__TaintedBranch *tb = (Panda__TaintedBranch *) malloc(sizeof(Panda__TaintedBranch));
                *tb = PANDA__TAINTED_BRANCH__INIT;
                tb->call_stack = pandalog_callstack_create();
                tb->n_taint_query = num_tainted;
                tb->taint_query = (Panda__TaintQuery **) malloc (sizeof (Panda__TaintQuery *) * num_tainted);
                uint32_t i=0;
                for (uint32_t o=0; o<size; o++) {
                    Addr ao = a;
                    ao.off = o;
                    if (taint2_query(ao)) {
                        tb->taint_query[i++] = taint2_query_pandalog(ao, o);
                    }
                }
                Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                ple.tainted_branch = tb;
                pandalog_write_entry(&ple);
                pandalog_callstack_free(tb->call_stack);
                for (uint32_t i=0; i<num_tainted; i++) {
                    pandalog_taint_query_free(tb->taint_query[i]);
                }
                free(tb);
            }
        }
    }
}


#endif

bool init_plugin(void *self) {
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_require("taint2");
    assert (init_taint2_api());    
    panda_arg_list *args = panda_get_args("tainted_instr");
    summary = panda_parse_bool_opt(args, "summary", "only print out a summary of tainted instructions");
    bool indirect_jumps = panda_parse_bool_opt(args, "indirect_jumps", "also query taint on indirect jumps and calls");
    liveness = panda_parse_bool_opt(args, "liveness", "track liveness of input bytes");
    if (summary) printf ("tainted_instr summary mode\n"); else printf ("tainted_instr full mode\n");
    /*
    panda_cb pcb;
    pcb.after_block_exec = tbranch_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    */
    PPP_REG_CB("taint2", on_branch2, tbranch_on_branch_taint2);
    if (indirect_jumps) 
        PPP_REG_CB("taint2", on_indirect_jump, tbranch_on_branch_taint2);
    return true;
}


void uninit_plugin(void *self) {
    if (summary) {
        Panda__TaintedBranchSummary *tbs = (Panda__TaintedBranchSummary *) malloc(sizeof(Panda__TaintedBranchSummary));
        for (auto kvp : tainted_branch) {
            uint64_t asid = kvp.first;
            for (auto pc : kvp.second) {
                *tbs = PANDA__TAINTED_BRANCH_SUMMARY__INIT;
                tbs->asid = asid;
                tbs->pc = pc;
                Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                ple.tainted_branch_summary = tbs;
                pandalog_write_entry(&ple);
            }
        }
        free(tbs);
    }    
    
}
