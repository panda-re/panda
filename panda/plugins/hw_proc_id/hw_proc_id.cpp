/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano          fasano@mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

// Simple plugin to provide an architecture-agnostic, generic capability
// for uniquely identifying a process withotu OSI.
//
// For non-mips architectures, we simply return the ASID. For MIPS
// we cache the address of the current processes' task_struct and return
// that.

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
#include "hw_proc_id_int_fns.h"
}


#ifdef TARGET_MIPS
target_ulong last_r28 = 0;

void r28_cache(CPUState *cpu, TranslationBlock *tb) {
  // Whenever the kernel changes register 28 (current task struct)
  // save it - Unless it's <= 0x80000000- then it's not the task struct(?)

  if (panda_in_kernel(cpu) && unlikely(((CPUMIPSState*)cpu->env_ptr)->active_tc.gpr[28] != last_r28)) {
      target_ulong potential = ((CPUMIPSState*)cpu->env_ptr)->active_tc.gpr[28];
      // XXX: af: While in kernel mode, r28 may be used to contain non-pointer values
      // make sure we don't cache one of those
      if (potential > 0x80000000) {
        last_r28 = potential;
      }
  }
}
#endif

unsigned int get_id(CPUState * cpu) {
#ifdef TARGET_MIPS
  return last_r28;
#else
  return panda_current_asid(cpu);
#endif
}

bool init_plugin(void *self) {
#if defined(TARGET_MIPS)
    panda_cb pcb = { .before_block_exec = r28_cache };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
#endif
    return true;
}

void uninit_plugin(void *self) { }
