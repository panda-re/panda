
#ifndef __PANDA_COMMON_H_
#define __PANDA_COMMON_H_

#include "cpu.h"


target_ulong panda_current_pc(CPUState *env);
target_ulong panda_current_asid(CPUState *env);

#endif
