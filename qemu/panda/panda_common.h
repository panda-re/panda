#ifndef __PANDA_COMMON_H_
#define __PANDA_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cpu.h"

target_ulong panda_current_pc(CPUState *env);
target_ulong panda_current_asid(CPUState *env);
bool panda_in_kernel(CPUState *env);

void panda_disas(FILE *out, void *code, unsigned long size);

#ifdef __cplusplus
}
#endif

#endif
