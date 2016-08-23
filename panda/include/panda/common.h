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

void panda_set_os_name(char *os_name);





hwaddr panda_virt_to_phys(CPUState *env, target_ulong addr);
int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                            uint8_t *buf, int len, int is_write);
int panda_virtual_memory_read(CPUState *env, target_ulong addr,
                              uint8_t *buf, int len);
int panda_virtual_memory_write(CPUState *env, target_ulong addr,
                               uint8_t *buf, int len);

#ifdef __cplusplus
}
#endif

#endif
