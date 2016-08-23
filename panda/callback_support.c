
#include "cpu.h"
#include "panda/plugin.h"
#include "rr_log.h"


target_phys_addr_t panda_virt_to_phys(CPUState *env, target_ulong addr){
    target_ulong page;
    target_phys_addr_t phys_addr;
    page = addr & TARGET_PAGE_MASK;
    phys_addr = cpu_get_phys_page_debug(env, page);
    /* if no physical page mapped, return an error */
    if (phys_addr == -1)
        return -1;
    phys_addr += (addr & ~TARGET_PAGE_MASK);
    return phys_addr;
}

int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                        uint8_t *buf, int len, int is_write)
{
    int l;
    int ret;
    target_phys_addr_t phys_addr;
    target_ulong page;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(env, page);
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        if (is_write)
            cpu_physical_memory_write_rom(phys_addr, buf, l);
        else {
            ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);
            if(ret < 0) return ret;
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}


int panda_virtual_memory_read(CPUState *env, target_ulong addr,
                              uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 0);
}


int panda_virtual_memory_write(CPUState *env, target_ulong addr,
                               uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 1);
}



// These are used in exec.c 
void panda_callbacks_before_dma(CPUState *cpu, hwaddr addr1, const uint8_t *buf, hwaddr l, int is_write) { 
    if (rr_mode == RR_REPLAY) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_BEFORE_DMA]; 
             plist != NULL; plist = panda_cb_list_next(plist)) {
            plist->entry.replay_before_dma(cpu_single_env, is_write, buf, addr1, l);
        }
    }
}

void panda_callbacks_after_dma(CPUState *cpu, hwaddr addr1, const uint8_t *buf, hwaddr l, int is_write) {
    if (rr_mode == RR_REPLAY) {
        panda_cb_list *plist;
       for (plist = panda_cbs[PANDA_CB_REPLAY_AFTER_DMA];
            plist != NULL; plist = panda_cb_list_next(plist)) {
            plist->entry.replay_after_dma(cpu_single_env, is_write, buf, addr1, l);
        }
    }
}

// These are used in cpu-exec.c 
void panda_callbacks_before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    panda_cb_list *plist;
    // If we got here we are definitely going to exec
    // this block. Clear the before_bb_invalidate_opt flag
    bb_invalidate_done = false;
    for (plist = panda_cbs[PANDA_CB_BEFORE_BLOCK_EXEC];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.before_block_exec(env, tb);
    }
}


void panda_callbacks_after_block_exec(CPUState *cpu, TranslateionBlock *tb, TranslationBlock *next_tb) {    
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_AFTER_BLOCK_EXEC]; 
         plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.after_block_exec(env, tb, (TranslationBlock *)(next_tb & ~3));
    }
}


void panda_callbacks_before_block_translate(CPUState *cpu, target_ulong pc) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_BEFORE_BLOCK_TRANSLATE];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.before_block_translate(env, pc);
    }
}


void panda_callbacks_after_block_translate(CPUState *cpu, target_ulong pc) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_AFTER_BLOCK_TRANSLATE];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.after_block_translate(env, pc);
    }
}


void panda_callbacks_before_find_fast() {
    if (panda_plugin_to_unload){
        panda_plugin_to_unload = false;
        int i;
        for (i = 0; i < MAX_PANDA_PLUGINS; i++){
            if (panda_plugins_to_unload[i]){
                panda_do_unload_plugin(i);
                panda_plugins_to_unload[i] = false;
            }
        }
    }    
    if (panda_flush_tb()) {
        tb_flush(env);
        tb_invalidated_flag = 1;
    }
}


TranslationBlock *panda_callbacks_after_find_fast(CPUState *cpu, TranslationBlock *tb) {
    // PANDA instrumentation: before basic block exec (with option
    // to invalidate tb)
    // Note: we can hit this point multiple times without actually having
    // executed the block in question if there are interrupts pending.
    // So we guard the callback execution with bb_invalidate_done, which
    // will get cleared when we actually get to execute the basic block.
    panda_cb_list *plist;
    bool panda_invalidate_tb = false;
    if (unlikely(!bb_invalidate_done)) {
        for(plist = panda_cbs[PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT];
            plist != NULL; plist = panda_cb_list_next(plist)) {
            panda_invalidate_tb |=
                plist->entry.before_block_exec_invalidate_opt(env, tb);
        }
        bb_invalidate_done = true;
    }    
#ifdef CONFIG_SOFTMMU
    if (panda_invalidate_tb ||
        (rr_mode == RR_REPLAY && rr_num_instr_before_next_interrupt > 0 &&
         tb->num_guest_insns > rr_num_instr_before_next_interrupt)) {
        //mz invalidate current TB and retranslate
        invalidate_single_tb(env, tb->pc);
        //mz try again.
        tb = tb_find_fast(env);
    }    
    /* Note: we do it here to avoid a gcc bug on Mac OS X when
       doing it in tb_find_slow */
    if (tb_invalidated_flag) {
        /* as some TB could have been invalidated because
           of memory exceptions while generating the code, we
           must recompute the hash index here */
        next_tb = 0;
        tb_invalidated_flag = 0;
    }
#endif //CONFIG_SOFTMMU    
    return tb;
}    


// These are used in target-i386/translate.c 
bool panda_callbacks_insn_translate(CPUState *env, target_ulong pc) {
    panda_cb_list *plist;
    bool panda_exec_cb = false;
    for(plist = panda_cbs[PANDA_CB_INSN_TRANSLATE]; plist != NULL; 
        plist = panda_cb_list_next(plist)) {
        panda_exec_cb |= plist->entry.insn_translate(env, pc_ptr);
    }
    return panda_exec_cb;
}


// These are used in softmmu_template.h
void panda_callbacks_before_mem_read(CPUState *env, target_ulong pc, 
                                     target_ulong addr, uint32_t data_size) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_VIRT_MEM_BEFORE_READ]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.virt_mem_before_read(env, env->panda_guest_pc, addr, data_size);
    }
    hwaddr paddr = panda_virt_to_phys(env, addr);
    for(plist = panda_cbs[PANDA_CB_PHYS_MEM_BEFORE_READ]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.phys_mem_before_read(env, env->panda_guest_pc, paddr, data_size);
    }
}


void panda_callbacks_callbacks_after_mem_read(CPUState *env, target_ulong pc, 
                                              target_ulong addr, uint32_t data_size, 
                                              uint64_t *pres) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_VIRT_MEM_AFTER_READ]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.virt_mem_after_read(env, env->panda_guest_pc, addr, data_size, pres);
    }
    hwaddr paddr = panda_virt_to_phys(env, addr);
    for(plist = panda_cbs[PANDA_CB_PHYS_MEM_AFTER_READ]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.phys_mem_after_read(env, env->panda_guest_pc, paddr, data_size, pres);
    }
}


void panda_callbacks_before_mem_write(CPUState *env, target_ulong pc, 
                                      target_ulong addr, uint32_t data_size,
                                      uint64_t *pval) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_VIRT_MEM_BEFORE_WRITE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.virt_mem_before_write(env, env->panda_guest_pc, addr,
                                           data_size, pval);
    }
    hwaddr paddr = panda_virt_to_phys(env, addr);
    for(plist = panda_cbs[PANDA_CB_PHYS_MEM_BEFORE_WRITE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.phys_mem_before_write(env, env->panda_guest_pc, paddr, data_size, pval);
    }
}


void panda_callbacks_after_mem_write(CPUState *env, target_ulong pc, 
                                     target_ulong addr, uint32_t data_size, 
                                     uint64_t *pval) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_VIRT_MEM_AFTER_WRITE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.virt_mem_after_write(env, env->panda_guest_pc, addr,
                                          data_size, pval);
    }
    hwaddr paddr = panda_virt_to_phys(env, addr);
    for(plist = panda_cbs[PANDA_CB_PHYS_MEM_AFTER_WRITE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.phys_mem_after_write(env, env->panda_guest_pc, paddr, data_size, pval);
    }
}


// target-i386/misc_helpers.c
void panda_callbacks_cpuid(CPUState *env) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_GUEST_HYPERCALL]; plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.guest_hypercall(env);
    }
}


void panda_callbacks_cpu_restore_state(CPUState *env, TranslationBlock *tb) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_CPU_RESTORE_STATE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        plist->entry.cb_cpu_restore_state(env, tb);
    }
}


void panda_callbacks_asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_ASID_CHANGED]; plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.asid_change(env, old_asid, new_asid);
    }
}


