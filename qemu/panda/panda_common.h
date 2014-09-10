#ifndef __PANDA_COMMON_H_
#define __PANDA_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cpu.h"

#ifdef __cplusplus
}
#endif

target_ulong panda_current_pc(CPUState *env);
target_ulong panda_current_asid(CPUState *env);

#endif
