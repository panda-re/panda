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

#include <dlfcn.h>
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "../taint/taint_processor.h"
#include "../taint/taint_ext.h"
#include "rr_log.h"
}


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU
uint32_t last_max_obs_ls_type = 0;

int tcn_before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (taint_enabled()) {
        uint32_t n = taint_max_obs_ls_type();
        if (n > last_max_obs_ls_type) {
            printf ("tcn changed.  tb->pc=0x%lx  rr_instr_count=%d  tcn=%d\n",
                    tb->pc, rr_get_guest_instr_count(), n);
            last_max_obs_ls_type = n;
        }
    }
}


#endif

bool init_plugin(void *self) {

#ifdef CONFIG_SOFTMMU
  // this sets up the taint api fn ptrs so we have access
  bool x = init_taint_api();  
  assert (x==true);

  panda_cb pcb;
  pcb.before_block_exec = tcn_before_block_exec;
  panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

  return true;
#else
  fprintf(stderr, "tcn plugin does not support linux-user mode\n");
  return false;
#endif
}


void uninit_plugin(void *self) {
}
