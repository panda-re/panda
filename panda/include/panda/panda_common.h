#ifndef __PANDA_COMMON_H__
#define __PANDA_COMMON_H__


void panda_cleanup(void);
void panda_set_os_name(char *os_name);
void panda_before_find_fast(void);
void panda_disas(FILE *out, void *code, unsigned long size);

/*
 * @brief Returns the guest address space identifier.
 */
target_ulong panda_current_asid(CPUState *env);

/**
 * @brief Returns the guest program counter.
 */
target_ulong panda_current_pc(CPUState *cpu);




#endif
