#include <assert.h>
#include <stdint.h>

extern "C" {
#include "panda_plugin.h"
}
#include "panda_common.h"

target_ulong panda_current_pc(CPUState *env) {
  assert (panda_update_pc);
  return env->panda_guest_pc;
}

#ifdef TARGET_ARM
// ARM: stolen from target-arm/helper.c
static uint32_t arm_get_vaddr_table(CPUState *env, uint32_t address)
{
  uint32_t table;

  if (address & env->cp15.c2_mask)
    table = env->cp15.c2_base1 & 0xffffc000;
  else
    table = env->cp15.c2_base0 & env->cp15.c2_base_mask;

  return table;
}
#endif

/*
  returns current asid or address-space id.
  architecture-independent
*/
target_ulong panda_current_asid(CPUState *env) {
#if (defined TARGET_I386 || defined TARGET_X86_64)
  return env->cr[3];
#elif defined(TARGET_ARM)
  return arm_get_vaddr_table(env, panda_current_pc(env));
#else
  return 0;
#endif
}
