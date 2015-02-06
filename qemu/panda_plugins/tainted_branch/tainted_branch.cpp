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
//FILE *branchfile = NULL;

bool use_taint2 = true;

void callstack() {
    // callstack info
    target_ulong callers[16];
    int n = get_callers(callers, 16, cpu_single_env);
    for (int i=0; i<n; i++) {
        printf ("callstack: %d " TARGET_FMT_lx " \n", i, callers[i]);
    }
}



uint32_t *label = NULL;
uint32_t num_labels = 0;
uint32_t max_num_labels = 0;

// el is a label
int tb_each_label(uint32_t el, void *stuff1) {
    
    if (max_num_labels == 0) {
        max_num_labels = 16;
        label = (uint32_t *) malloc(sizeof(uint32_t) * max_num_labels);
    }
    else {
        if (num_labels == max_num_labels) {
            max_num_labels *= 2;
            label = (uint32_t *) realloc(label, sizeof(uint32_t) * max_num_labels);
        }
    }
    label[num_labels] = el;
    num_labels ++;

    // continue iteration
    return 0;
}


#define MAXCALLERS 128
target_ulong callers[MAXCALLERS];
uint64_t callers64[MAXCALLERS];
uint32_t num_callers = 0;


void tbranch_pandalogging() {
    if (num_labels == 0) {
        // no actual labels -- why isn't this handled by taint_query_llvm ? 
        return;
    }
    int n = get_callers(callers, MAXCALLERS, cpu_single_env);
    /*
    if (callers64 == NULL) {
        max_num_callers = std::max(n, 16);
        callers = (target_ulong *) malloc(sizeof(target_ulong) * max_num_callers);
        callers64 = (uint64_t *) malloc(sizeof(uint64_t) * max_num_callers);                
    }
    if (n >= max_num_callers) {
        do {
            max_num_callers *= 2;
        } while (n >= max_num_callers);
        callers = (target_ulong *) realloc(callers64, sizeof(target_ulong) * max_num_callers);
        callers64 = (uint64_t *) realloc(callers64, sizeof(uint64_t) * max_num_callers);
    }
    */
    for (unsigned int i=0; i<n; i++) {
        callers64[i] = callers[i];
    }
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.n_tainted_branch_label = num_labels;
    ple.tainted_branch_label = label;
    ple.n_callstack = n;
    ple.callstack = callers64;
    pandalog_write_entry(&ple);           
}


void tbranch_on_branch(uint64_t pc, int reg_num) {
    if (pandalog) {
        for (uint32_t offset=0; offset<8; offset++) {
            if (taint_query_llvm(reg_num, offset)) {
                num_labels = 0;
                taint_labelset_llvm_iter(reg_num, 0, tb_each_label, NULL);            
                tbranch_pandalogging();
            }
        }
    }
}



void tbranch_on_branch_taint2(uint64_t reg_num) {
    if (pandalog) {
        for (uint32_t offset=0; offset<8; offset++) {
            if (taint2_query_llvm(reg_num, offset)) {
                num_labels = 0;
                taint2_labelset_llvm_iter(reg_num, offset, tb_each_label, NULL);
                tbranch_pandalogging();
            }
        }
    }
}


int tbranch_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
    if ((use_taint2 && taint2_enabled()) || (!use_taint2 && taint_enabled())) {
        if (first_enable_taint) {
            if (use_taint2) { PPP_REG_CB("taint2", on_branch2, tbranch_on_branch_taint2); }
            else { PPP_REG_CB("taint", on_branch, tbranch_on_branch); }
            first_enable_taint = false;
            printf ("turning on tainted_branch before / after execute_taint_ops callbacs\n");
        }
    }
    return 0;
}

#endif

bool init_plugin(void *self) {
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_cb pcb;
    pcb.after_block_exec = tbranch_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    panda_arg_list *args = panda_get_args("tainted_branch");
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
    //    fclose(branchfile);
}
