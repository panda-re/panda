/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano          fasano@mit.edu
 *  Luke Craig             luke.craig@ll.mit.edu
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

#ifdef TARGET_MIPS64
uint64_t KERNEL_STACK_SIZE = 8192;  //8KB
uint64_t STACK_MASK = ~(KERNEL_STACK_SIZE - 1);
#else
uint64_t STACK_MASK = (target_ptr_t)-1;
#endif

#if defined(TARGET_MIPS)
target_ulong last_r28 = 0;
bool initialized = false;

/**
 * @brief Cache the last R28 observed while in kernel for MIPS/MIPS64
 *
 * On MIPS/MIPS64 in kernel mode, r28 points to the location of the current
 * task_struct. We need to cache this value for use in usermode.
 */
inline void check_cache_r28(CPUState *cpu) {
  CPUMIPSState *mips_env = (CPUMIPSState *)cpu->env_ptr;
  target_ulong r28_value = mips_env->active_tc.gpr[28] & STACK_MASK;
  if (panda_in_kernel(cpu) && unlikely(r28_value != last_r28)) {
    // XXX: af: While in kernel mode, r28 may be used to contain non-pointer
    // values
    // Make sure we don't cache one of those, so we check if r28 contains
    // a pointer to kernel memory
    if (likely(address_in_kernel_code_linux(r28_value))) {
      last_r28 = r28_value;
      initialized = true;
    }
  }
}

void r28_cache(CPUState *cpu, TranslationBlock *tb) {
    check_cache_r28(cpu);
}
#endif


/**
 * @brief Returns true if all prerequisite values to determine hwid cached.
 * 
 * Realistically this is only relevant for MIPS.
 */
bool id_is_initialized(void){
  #ifdef TARGET_MIPS
  return initialized;
  #else
  return true;
  #endif
}

/**
 * @brief Returns a hardware-based process ID for the current process.
 * 
 * This is a wrapper around ASID that takes into the oddity that is MIPS.
 * 
 * @param cpu 
 * @return target_ulong
 */
target_ulong get_id(CPUState * cpu) {
#ifdef TARGET_MIPS
  if (!id_is_initialized()) {
    // try to initialize before returning
    check_cache_r28(cpu);
  }
  return last_r28;
#else
  return panda_current_asid(cpu);
#endif
}

bool init_plugin(void *self) {
#if defined(TARGET_MIPS)
    panda_cb pcb = { .start_block_exec = r28_cache };
    panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb);
#endif
    return true;
}

void uninit_plugin(void *self) { }
