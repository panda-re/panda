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

#include "pandalog.h"

#include "panda_plugin.h"
#include "../taint2/taint2_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"
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

bool summary = false;

#include <map>
#include <set>

// map from asid -> pc
std::map<uint64_t,std::set<uint64_t>> tainted_branch;


void tbranch_on_branch_taint2(Addr a) {
    if (pandalog) {
        // a is an llvm reg
        assert (a.typ == LADDR);
        // count number of tainted bytes on this reg
        // NB: assuming 8 bytes
        uint32_t num_tainted = 0;
        for (uint32_t o=0; o<8; o++) {
            Addr ao =a;
            ao.off = o;
            num_tainted += (taint2_query(ao) != 0);
        }
        if (num_tainted > 0) {
            if (summary) {
                extern CPUState *cpu_single_env;
                CPUState *env = cpu_single_env;
                target_ulong asid = panda_current_asid(env);
                tainted_branch[asid].insert(panda_current_pc(env));
            }
            else {
                Panda__TaintedBranch *tb = (Panda__TaintedBranch *) malloc(sizeof(Panda__TaintedBranch));
                *tb = PANDA__TAINTED_BRANCH__INIT;
                tb->call_stack = pandalog_callstack_create();
                tb->n_taint_query = num_tainted;
                tb->taint_query = (Panda__TaintQuery **) malloc (sizeof (Panda__TaintQuery *) * num_tainted);
                uint32_t i=0;
                for (uint32_t o=0; o<8; o++) {
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
    summary = panda_parse_bool(args, "summary");
    if (summary) printf ("tainted_instr summary mode\n"); else printf ("tainted_instr full mode\n");
    /*
    panda_cb pcb;
    pcb.after_block_exec = tbranch_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    */
    PPP_REG_CB("taint2", on_branch2, tbranch_on_branch_taint2);                                                                       
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
