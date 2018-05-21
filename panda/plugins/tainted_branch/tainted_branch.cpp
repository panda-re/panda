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
  taint_branch plugin

  Queries taint at conditional branches and indirect jumps and
  pandalogs results.  Two modes, standard and summary.
  
  Conditional branch.

  If the register containing data used to decide a branch is tainted,
  the taint system callback on_branch2 runs, which means
  tainted_cond_branch in this plugin runs and is passed two args: addr
  and size of the register.  This calls a helper that either pandalogs
  the results (see below) or collects summary info.

  Indirect jump.

  If the register containing the address to which we are about to jump
  is tainted, the taint system callback on_indirect_jmp runs, which
  means tainted_ind_jmp in this plugin runs and is passed two args:
  addr and size of the register. This calls a helper that either
  pandalogs the results (see below) or collects summary info.

  For each register (either cond branch or ind jmp) if there is any
  taint on it, we do the following.

  * standard mode: pandalogs the result of querying taint on every
    byte in the register, as well as call_stack, asid, and 
    is_cond=true/false

  * summary: collects set of tainted cond jmp and indirect jump instructions 
    (program counters) by asid.

  Summary mode spits out asid sets at the end of the replay to stdout.



*/


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
#include <stdio.h>
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

target_ulong current_bb_start_pc;

bool summary = false;
bool liveness = false;

#include <map>
#include <set>

// map from asid -> pc
std::map<uint64_t,std::set<uint64_t>> tainted_cond;
std::map<uint64_t,std::set<uint64_t>> tainted_jmp;


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


void log_tbranch(Addr a, uint64_t size, bool is_cond) {
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
//        printf ("we have some taint -- instr=%" PRId64 " size=%d is_cond=%d\n", rr_get_guest_instr_count(), (int) size, (int) is_cond);
        if (liveness) {
            // update liveness info for all input bytes from which lval derives
            for (uint32_t o=0; o<size; o++) {
                ao.off = o;
                taint2_labelset_addr_iter(a, taint_branch_aux, NULL);
            }        
        }
        CPUState *cpu = first_cpu;
        target_ulong asid = panda_current_asid(cpu);
        if (summary) {
            if (is_cond) 
                tainted_cond[asid].insert(panda_current_pc(cpu));
            else
                tainted_jmp[asid].insert(panda_current_pc(cpu));
        }
        else {
            Panda__TaintedBranch *tb = (Panda__TaintedBranch *) malloc(sizeof(Panda__TaintedBranch));
            *tb = PANDA__TAINTED_BRANCH__INIT;
            tb->call_stack = pandalog_callstack_create();
            tb->n_taint_query = num_tainted;
            tb->is_cond = is_cond;
            tb->asid = asid;
            tb->bb_start_pc = current_bb_start_pc;
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



void tainted_cond_branch(Addr a, uint64_t size) {
    log_tbranch(a,size,true);
}

void tainted_ind_jump(Addr a, uint64_t size) {
    log_tbranch(a,size,false);    
}


int before_block_exec(CPUState *env, TranslationBlock *tb) {
    current_bb_start_pc = tb->pc;
    return 0;
}


#endif

bool init_plugin(void *self) {
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_require("taint2");
    assert (init_taint2_api());    
    panda_enable_precise_pc();
    panda_arg_list *args = panda_get_args("tainted_branch");
    summary = panda_parse_bool_opt(args, "summary", "only print out a summary of tainted instructions");
    if (!summary) assert(pandalog);
    bool indirect_jumps = panda_parse_bool_opt(args, "indirect_jumps", "also query taint on indirect jumps and calls");
    liveness = panda_parse_bool_opt(args, "liveness", "track liveness of input bytes");
    if (summary) 
        printf ("tainted_branch summary mode\n"); 
    else
        printf ("tainted_branch full mode\n");

    panda_cb pcb;

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    PPP_REG_CB("taint2", on_branch2, tainted_cond_branch); 
    if (indirect_jumps) 
        PPP_REG_CB("taint2", on_indirect_jump, tainted_ind_jump); 
    return true;
}


void uninit_plugin(void *self) {
    if (summary) {
       //  Panda__TaintedBranchSummary *tbs = (Panda__TaintedBranchSummary *) malloc(sizeof(Panda__TaintedBranchSummary));
        printf ("Writing summary file for tainted_branch\n");
        FILE *fp = fopen("tainted_branch", "w");
        fprintf(fp, "%d tainted conditionals\n", (int) tainted_cond.size());
        for (auto kvp : tainted_cond) {
            uint64_t asid = kvp.first;
            fprintf(fp, "asid=%" PRIx64 "\n", asid);
            for (auto  pc : tainted_cond[asid])
                fprintf(fp, "  pc=%" PRIx64 "\n", pc);            
        }
        fprintf(fp, "%d tainted jumps\n", (int) tainted_jmp.size());
        for (auto kvp : tainted_jmp) {
            uint64_t asid = kvp.first;
            fprintf(fp, "asid=%" PRIx64 "\n", asid);
            for (auto pc : kvp.second) 
                fprintf(fp, "  pc=%" PRIx64 "\n", pc);
        }        
        fclose(fp);
    }        
}
