#ifndef __PANDA_CALLBACK_SUPPORT_H__
#define __PANDA_CALLBACK_SUPPORT_H__

// exec.c
void panda_callbacks_before_dma(CPUState *cpu, hwaddr addr1, const uint8_t *buf, hwaddr l, int is_write);
void panda_callbacks_after_dma(CPUState *cpu, hwaddr addr1, const uint8_t *buf, hwaddr l, int is_write);
// cpu-exec.c
void panda_callbacks_before_block_exec(CPUState *cpu, TranslationBlock *tb);
void panda_callbacks_after_block_exec(CPUState *cpu, TranslationBlock *tb);
void panda_callbacks_before_block_translate(CPUState *cpu, target_ulong pc);
void panda_callbacks_after_block_translate(CPUState *cpu, TranslationBlock *tb);
bool panda_callbacks_after_find_fast(CPUState *cpu, TranslationBlock *tb, bool panda_bb_invalidate_done, bool *invalidate);

// target-i386/translate.c
bool panda_callbacks_insn_translate(CPUState *env, target_ulong pc);
// softmmu_template.h
void panda_callbacks_before_mem_read(CPUState *env, target_ulong pc, target_ulong addr,
                                     uint32_t data_size, void *ram_ptr);
void panda_callbacks_after_mem_read(CPUState *env, target_ulong pc, target_ulong addr,
                                    uint32_t data_size, uint64_t result, void *ram_ptr);
void panda_callbacks_before_mem_write(CPUState *env, target_ulong pc, target_ulong addr,
                                      uint32_t data_size, uint64_t result, void *ram_ptr);
void panda_callbacks_after_mem_write(CPUState *env, target_ulong pc, target_ulong addr,
                                     uint32_t data_size, uint64_t val, void *ram_ptr);
// target-i386/misc_helper.c
void panda_callbacks_cpuid(CPUState *env);
// translate-all.c
void panda_callbacks_cpu_restore_state(CPUState *env, TranslationBlock *tb);
// target-i386/helper.c
void panda_callbacks_asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid);
// vl.c
void panda_callbacks_after_machine_init(void);

#endif
