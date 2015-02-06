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

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "../taint2/taint2_ext.h"
#include "../taint/taint_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"
#include "pandalog.h"
#include "panda_common.h"
#include "guestarch.h"
}


#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

//#include "../taint/taint_processor.h"

typedef void (*on_branch_t) (uint64_t, int); // hack since we can't include both taint.h's

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU


bool first_enable_taint = true;

bool use_taint2 = false;

void callstack() {
    // callstack info
    target_ulong callers[16];
    int n = get_callers(callers, 16, cpu_single_env);
    for (int i=0; i<n; i++) {
        printf ("callstack: %d " TARGET_FMT_lx " \n", i, callers[i]);
    }
}


/*
 dead_data[l] is a count of the number of number of times the label l
 was seen to be involved in a tainted branche.  If l is a positional
 label, then this is the number of times byte l in the labeled region (file?)
 was used to decide some branch.
 
 This is a possible measure of the "deadness" of data.  If a particular
 byte in the input is never used to decide any branches, then it can be assigned to 
 any value without that causing any change in control-flow.
 The higher this number is, the more branches depend upon this data and thus
 the less likely that it can be considered dead.  

*/
std::map < uint32_t, uint32_t > dead_data;


bool first_time = true;

void dd_spit(){
    FILE *fp;
    if (first_time) {
        first_time = false;
        fp = fopen("dead_data", "w");
    }
    else {
        fp = fopen("dead_data", "a");
    }
    fprintf (fp,"\n\n-----------------------------------------\n");
    fprintf (fp, "Dead Data Summary\n");
    for ( auto &kvp : dead_data ) {
        uint32_t el = kvp.first;
        uint32_t count = kvp.second;
        fprintf (fp, "%6d %d\n", el, count);
    }
    fclose(fp);
}



// el is a label
int dd_each_label(uint32_t el, void *stuff1) {
    dead_data[el] += 1;    
    // continue iteration
    return 0;
}


uint64_t *callers64=NULL;
uint32_t num_callers = 0;



void dead_data_on_branch(uint64_t pc, int reg_num) {
    for (uint32_t offset=0; offset<8; offset++) {
        if (taint_query_llvm(reg_num, offset)) {           
            taint_labelset_llvm_iter(reg_num, offset, dd_each_label, NULL);
        }
    }
}

void dead_data_on_branch_taint2(uint64_t reg_num) {
    for (uint32_t offset=0; offset<8; offset++) {
        if (taint2_query_llvm(reg_num, offset)) {           
            printf ("dead_data_on_branch_taint2 offset=%d is tainted\n", offset);
            taint2_labelset_llvm_iter(reg_num, offset, dd_each_label, NULL);
        }
    }
}



uint64_t ii = 0;
int dead_data_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {

    ii ++;
    if ((ii % 1000) == 0) {
        dd_spit();
    }

    if ((use_taint2 && taint2_enabled()) || (!use_taint2 && taint_enabled())) {
        if (first_enable_taint) {
            if (use_taint2) { PPP_REG_CB("taint2", on_branch2, dead_data_on_branch_taint2); }
            else { PPP_REG_CB("taint", on_branch, dead_data_on_branch); }
            first_enable_taint = false;
            printf ("enabling on_branch taint api callbacks\n");
        }
    }
    return 0;
}


#endif

bool init_plugin(void *self) {
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_cb pcb;
    pcb.after_block_exec = dead_data_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    panda_arg_list *args = panda_get_args("dead_data");
    use_taint2 = !panda_parse_bool(args, "taint1");
    if (use_taint2) {
        panda_require("taint2");
        assert (init_taint2_api());
    }
    else {
        panda_require("taint");
        assert (init_taint_api());
    }
    
    //    branchfile = fopen("branches.txt", "w");
    return true;
}

void uninit_plugin(void *self) {
    dd_spit();
}
