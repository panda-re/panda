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

#include "../taint/taint.h"

extern "C" {

#include <dlfcn.h>
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
#include <stdlib.h>
#include <ctype.h>
#include <math.h>

#include "../taint/taint_processor.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU


uint32_t tcn_before = 0;

bool first_enable_taint = true;


void taint_compute_numbers_before_execute_taint_ops(void) {
    // about to process taint corresponding to that block.
    // clear the did-tainted-computation-happen flag
    taint_clear_tainted_computation_happened();
    taint_clear_taint_state_changed();
    taint_clear_taint_state_read();
    tcn_before = taint_max_obs_ls_type();
}


static uint64_t the_pc;
static uint64_t the_instr_count;

int taint_compute_numbers_before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (taint_enabled()) {
        // just store pc
        the_pc = tb->pc;
        the_instr_count = rr_get_guest_instr_count();
    }
    return 0;
}


void taint_compute_numbers_after_execute_taint_ops(void) {
    uint32_t tcn_after = taint_max_obs_ls_type();
    if (tcn_after != tcn_before) {
        printf ("tcn changed.  the_pc=0x%" PRIx64 "  rr_instr_count=%" PRIu64 "  max_obs_tcn=%" PRIu32 "\n",
                the_pc, the_instr_count, taint_max_obs_ls_type());
    }
    if (taint_tainted_computation_happened()) {
        // the last run of the taint processor on a basic block included
        // at least one taint compute in which at least one arg was tainted 
        // and thus, some taint compute number increased
        printf ("tainted computation happened.  the_pc=0x%" PRIx64 "  rr_instr_count=%" PRIu64 "  max_obs_tcn=%" PRIu32 "\n",
                the_pc, the_instr_count, taint_max_obs_ls_type());
    }
    if (taint_taint_state_changed()) {
        // some change to taint state
        printf ("taint state changed.  the_pc=0x%" PRIx64 "  rr_instr_count=%" PRIu64 "  max_obs_tcn=%" PRIu32 "\n",
                the_pc, the_instr_count, taint_max_obs_ls_type());
    }
    if (taint_taint_state_read()) {
        printf ("taint state read.  the_pc=0x%" PRIx64 "  rr_instr_count=%" PRIu64 "  max_obs_tcn=%" PRIu32 "\n",
                the_pc, the_instr_count, taint_max_obs_ls_type());
    }    
}

    
void taint_compute_numbers_on_load(uint64_t pc, uint64_t phys_addr) {
    if (taint_query_ram(phys_addr)) {
        printf ("pc=0x%" PRIx64 " -- load of tainted datat\n", pc);
    }
}

int taint_compute_numbers_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
    if (taint_enabled()) {
        if (first_enable_taint) {
            // just add the callbacks for before / after taint processor executes
            PPP_REG_CB("taint", before_execute_taint_ops, taint_compute_numbers_before_execute_taint_ops);
            PPP_REG_CB("taint", after_execute_taint_ops, taint_compute_numbers_after_execute_taint_ops);
            PPP_REG_CB("taint", on_load, taint_compute_numbers_on_load);    
            first_enable_taint = false;
            printf ("turning on tcn before / after execute_taint_ops callbacs\n");
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
  pcb.before_block_exec = taint_compute_numbers_before_block_exec;
  panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

  pcb.after_block_exec = taint_compute_numbers_after_block_exec;
  panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

  return true;
#else
  fprintf(stderr, "tcn plugin does not support linux-user mode\n");
  return false;
#endif
}


void uninit_plugin(void *self) {
}
