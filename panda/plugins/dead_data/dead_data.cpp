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

#include <map>
#include <vector>

#include "panda/panda_addr.h"

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "rr_log.h"    
#include "pandalog.h"
#include "panda_plugin.h"
#include "../taint2/taint2_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"
#include "panda_common.h"
#include "guestarch.h"
}


#include "../common/prog_point.h"

#include "../taint2/taint2.h"


extern uint64_t replay_get_guest_instr_count(void);
extern uint64_t replay_get_total_num_instructions(void);


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU

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

// dde[l] is a vector of instructions at which 
// this label was observed to participate in a tainted branch
std::map < uint32_t, float > dead_data; 

uint64_t first_tainted_branch = 0xffffffffffffffff;
uint64_t last_tainted_branch = 0;


const char *dead_data_filename;

void dd_spit(){
    if (pandalog) {
        printf ("computing dead data and writing to pandalog\n");
    }
    else {
        printf ("computing dead data and writing to stdout\n");
    }

    uint32_t *al = taint2_labels_applied();
    uint32_t n = taint2_num_labels_applied();
    for (uint32_t i=0; i<n; i++) {
        uint32_t l = al[i];
        if (dead_data.count(l) == 0) {
            dead_data[l] = 0;
        }
    }
    free(al);

    /*
    for ( auto &kvp : dde ) {
        uint32_t l = kvp.first;
        for ( auto &ins : kvp.second ) {
            dead_data[l] += ((float)(last_tainted_branch - ins) / denom);
            //dead_data[l] ++;
        }
    }
    */
    

    if (pandalog) {
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.n_dead_data = n;
        ple.dead_data =  (float *) malloc(sizeof(float) * n);
        for (uint32_t i=0; i<n; i++) {
            ple.dead_data[i] = dead_data[i];
        }
        pandalog_write_entry(&ple);
    }
    else {
        printf ("\n\n-----------------------------------------\n");
        printf ("Dead Data Summary\n");
        for ( auto &kvp : dead_data ) {
            uint32_t el = kvp.first;
            float val = kvp.second;
            printf ("%6d %0.2f\n", el, val);
        }
    }
}



 
 
// only compute dead data based on first N tainted branches a label 
// involved in.  N is MAX_INSTR_PER_EL
#define MAX_INSTR_PER_EL 100000

 
uint64_t current_instr;
uint64_t total_instr;

// el is a label
int dd_each_label(uint32_t el, void *stuff1) {
    dead_data[el] += ((float)(total_instr - current_instr)) / ((float)total_instr);
    // continue iteration
    return 0;
}




uint64_t *callers64=NULL;
uint32_t num_callers = 0;


void dead_data_on_branch(Addr a) {
    assert (a.typ == LADDR);
    LAddr reg_num = a.val.la;       
    current_instr = rr_get_guest_instr_count();
    for (uint32_t offset=0; offset<8; offset++) {
        if (taint2_query_llvm(reg_num, offset)) {           
            // this offset of reg is tainted.
            // iterate over labels in set & update dead data
            taint2_labelset_llvm_iter(reg_num, offset, dd_each_label, NULL);
        }
    }
}


bool first_enable_taint = true;


int dead_data_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
    if ((taint2_enabled()) && (first_enable_taint)) {
        first_enable_taint = false;        
        total_instr = replay_get_total_num_instructions();
        PPP_REG_CB("taint2", on_branch2, dead_data_on_branch);
        printf ("enabling on_branch taint api callbacks\n");
    }
    return 0;
}


#endif

bool init_plugin(void *self) {
    //    panda_require("callstack_instr");
    //    assert (init_callstack_instr_api());
    panda_cb pcb;
    pcb.after_block_exec = dead_data_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    panda_require("taint2");
    assert (init_taint2_api());
    return true;
}

void uninit_plugin(void *self) {
    dd_spit();
}
