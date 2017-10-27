#ifndef __PANDA_COMMON_H_
#define __PANDA_COMMON_H_

#include "cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

target_ulong panda_current_pc(CPUState *env);
target_ulong panda_current_asid(CPUState *env);
target_ulong panda_current_sp(CPUState *env);
bool panda_in_kernel(CPUState *env);

void panda_disas(FILE *out, void *code, unsigned long size);

void panda_set_os_name(char *os_name);





// is_write == 1 means this is a write to the virtual memory addr of the contents of buf.
// is_write == 0 is a read from that addr into buf.  
int panda_physical_memory_rw(hwaddr addr, uint8_t *buf, int len, int is_write);

hwaddr panda_virt_to_phys(CPUState *env, target_ulong addr);

int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                            uint8_t *buf, int len, int is_write);
int panda_virtual_memory_read(CPUState *env, target_ulong addr,
                              uint8_t *buf, int len);
int panda_virtual_memory_write(CPUState *env, target_ulong addr,
                               uint8_t *buf, int len);


void panda_before_find_fast(void);

#ifdef __cplusplus
}
#endif

#endif
