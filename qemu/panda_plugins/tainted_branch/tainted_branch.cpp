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
#include "../taint2/taint2_ext.h"
#include "../taint/taint_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"
#include "panda_common.h"
#include "guestarch.h"
}

#include <stdio.h>
#include "../taint2/label_set.h"
#include "../taint2/taint2.h"

typedef void (*on_branch_t) (uint64_t, int); // hack since we can't include both taint.h's

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU


bool first_enable_taint = true;
FILE *branchfile = NULL;

bool use_taint2 = true;

void tbranch_on_branch(uint64_t pc, int reg_num) {
    if (taint_query_llvm(reg_num, /*offset=*/0)) {
        printf("cr3=0x%x pc=0x%x Branch condition on tainted LLVM register: %%%d\n",
               (unsigned int ) panda_current_asid(cpu_single_env), (unsigned int) pc, reg_num);
        // Get taint compute number
        uint32_t ls_type = taint_get_ls_type_llvm(reg_num, /*offset=*/0);

        // Print out the labels
        printf("\tCompute number: %d\n", ls_type);
        //taint_spit_llvm(reg_num, /*offset=*/0);

        fprintf(branchfile, "%lx\n", pc);
    }
}

void tbranch_on_branch_taint2(LabelSetP ls, uint32_t tcn) {
    if (ls) {
        printf("cr3=0x%x pc=0x%x Branch condition on tainted LLVM register.\n",
               (unsigned int ) panda_current_asid(cpu_single_env),
               (unsigned int) panda_current_pc(cpu_single_env));

        // Print out the labels
        printf("\tCompute number: %lu\n", tcn);
        //taint2_labelset_spit(ls);
        fprintf(branchfile, "%lx\n", (uint64_t)panda_current_pc(cpu_single_env));

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

#ifdef CONFIG_SOFTMMU
  panda_cb pcb;
  pcb.after_block_exec = tbranch_after_block_exec;
  panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

  panda_arg_list *args = panda_get_args("tainted_branch");
  use_taint2 = !panda_parse_bool(args, "taint1");

  // this sets up the taint api fn ptrs so we have access
  if (use_taint2) assert(init_taint2_api());
  else assert(init_taint_api());

  branchfile = fopen("branches.txt", "w");

  return true;
#else
  fprintf(stderr, "tainted_branch plugin does not support linux-user mode\n");
  return false;
#endif
}

void uninit_plugin(void *self) {
    fclose(branchfile);
}
