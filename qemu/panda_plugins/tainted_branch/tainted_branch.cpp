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
#include "monitor.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "../taint/taint_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"
}

#include <stdio.h>
#include "../taint/taint_processor.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU


bool first_enable_taint = true;

void tbranch_on_branch(int reg_num) {
    if (taint_query_llvm(reg_num, /*offset=*/0)) {
        printf("Branch condition on tainted LLVM register: %%%d\n", reg_num);
        // Get taint compute number
        uint32_t ls_type = taint_get_ls_type_llvm(reg_num, /*offset=*/0);
        
        // Print out the labels
        printf("\tCompute number: %d\n", ls_type);
        taint_spit_llvm(reg_num, /*offset=*/0);
    }
}

int tbranch_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
    if (taint_enabled()) {
        if (first_enable_taint) {
            PPP_REG_CB("taint", on_branch, tbranch_on_branch);    
            first_enable_taint = false;
            printf ("turning on tainted_branch before / after execute_taint_ops callbacs\n");
        }
    }
    return 0;
}

#endif

bool init_plugin(void *self) {

#ifdef CONFIG_SOFTMMU
  // this sets up the taint api fn ptrs so we have access
  bool x = init_taint_api();  
  assert (x==true);

  panda_cb pcb;
  pcb.after_block_exec = tbranch_after_block_exec;
  panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

  return true;
#else
  fprintf(stderr, "tainted_branch plugin does not support linux-user mode\n");
  return false;
#endif
}

void uninit_plugin(void *self) {}
