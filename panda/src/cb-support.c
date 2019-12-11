#include <stdint.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "panda/plugin.h"
#include "panda/callbacks/cb-support.h"
#include "panda/common.h"

#include "panda/rr/rr_log.h"
#include "panda/rr/rr_api.h"
#include "exec/cpu-common.h"
#include "exec/ram_addr.h"

#define PCB(n) panda_callbacks_ ## n

void PCB(replay_hd_transfer)(CPUState *cpu, Hd_transfer_type type, target_ptr_t src_addr, target_ptr_t dest_addr, size_t num_bytes) {
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_HD_TRANSFER];
             plist != NULL;
             plist = panda_cb_list_next(plist)) {
                 if (plist->enabled) plist->entry.replay_hd_transfer(cpu, type, src_addr, dest_addr, num_bytes);
        }
    }
}

void PCB(replay_handle_packet)(CPUState *cpu, uint8_t *buf, size_t size, uint8_t direction, uint64_t buf_addr_rec) {
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_HANDLE_PACKET];
             plist != NULL;
             plist = panda_cb_list_next(plist)) {
                 if (plist->enabled) plist->entry.replay_handle_packet(cpu, buf, size, direction, buf_addr_rec);
        }
    }
}
void PCB(replay_net_transfer)(CPUState *cpu, Net_transfer_type type, uint64_t src_addr, uint64_t dst_addr, size_t num_bytes) {
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_NET_TRANSFER];
             plist != NULL;
             plist = panda_cb_list_next(plist)) {
                 if (plist->enabled) plist->entry.replay_net_transfer(cpu, type, src_addr, dst_addr, num_bytes);
        }
    }
}

// These are used in exec.c
void PCB(replay_before_dma)(CPUState *cpu, const uint8_t *buf, hwaddr addr, size_t size, bool is_write) {
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_BEFORE_DMA];
             plist != NULL; plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.replay_before_dma(cpu, buf, addr, size, is_write);
        }
    }
}

void PCB(replay_after_dma)(CPUState *cpu, const uint8_t *buf, hwaddr addr, size_t size, bool is_write) {
    if (rr_in_replay()) {
        panda_cb_list *plist;
       for (plist = panda_cbs[PANDA_CB_REPLAY_AFTER_DMA];
            plist != NULL; plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.replay_after_dma(cpu, buf, addr, size, is_write);
        }
    }
}

// These are used in cpu-exec.c
void PCB(before_block_exec)(CPUState *cpu, TranslationBlock *tb) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_BEFORE_BLOCK_EXEC];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.before_block_exec(cpu, tb);
    }
}


void PCB(after_block_exec)(CPUState *cpu, TranslationBlock *tb, uint8_t exitCode) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_AFTER_BLOCK_EXEC];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.after_block_exec(cpu, tb, exitCode);
    }
}


void PCB(before_block_translate)(CPUState *cpu, target_ptr_t pc) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_BEFORE_BLOCK_TRANSLATE];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.before_block_translate(cpu, pc);
    }
}


void PCB(after_block_translate)(CPUState *cpu, TranslationBlock *tb) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_AFTER_BLOCK_TRANSLATE];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.after_block_translate(cpu, tb);
    }
}

void PCB(before_find_fast)(void) {
    if (panda_plugin_to_unload) {
        panda_plugin_to_unload = false;
        for (int i = 0; i < MAX_PANDA_PLUGINS; i++) {
            if (panda_plugins_to_unload[i]) {
                panda_do_unload_plugin(i);
                panda_plugins_to_unload[i] = false;
            }
        }
    }
    if (panda_flush_tb()) {
        tb_flush(first_cpu);
    }
}

bool PCB(after_find_fast)(CPUState *cpu, TranslationBlock *tb,
                          bool bb_invalidate_done, bool *invalidate) {
    panda_cb_list *plist;
    if (!bb_invalidate_done) {
        for (plist = panda_cbs[PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT];
             plist != NULL; plist = panda_cb_list_next(plist)) {
            if (plist->enabled)
              *invalidate |=
                  plist->entry.before_block_exec_invalidate_opt(cpu, tb);
        }
        return true;
    }
    return false;
}

void PCB(after_cpu_exec_enter)(CPUState *cpu) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_AFTER_CPU_EXEC_ENTER];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.after_cpu_exec_enter(cpu);
    }
}

void PCB(before_cpu_exec_exit)(CPUState *cpu, bool ranBlock) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_BEFORE_CPU_EXEC_EXIT];
         plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.before_cpu_exec_exit(cpu, ranBlock);
    }
}

// These are used in target-i386/translate.c
bool PCB(insn_translate)(CPUState *env, target_ptr_t pc) {
    panda_cb_list *plist;
    bool panda_exec_cb = false;
    for(plist = panda_cbs[PANDA_CB_INSN_TRANSLATE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) 
          panda_exec_cb |= plist->entry.insn_translate(env, pc);
    }
    return panda_exec_cb;
}

bool PCB(after_insn_translate)(CPUState *env, target_ptr_t pc) {
    panda_cb_list *plist;
    bool panda_exec_cb = false;
    for(plist = panda_cbs[PANDA_CB_AFTER_INSN_TRANSLATE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) 
          panda_exec_cb |= plist->entry.after_insn_translate(env, pc);
    }
    return panda_exec_cb;
}

static inline hwaddr get_paddr(CPUState *cpu, target_ptr_t addr, void *ram_ptr) {
    if (!ram_ptr) {
        return panda_virt_to_phys(cpu, addr);
    }

    ram_addr_t offset = 0;
    RAMBlock *block = qemu_ram_block_from_host(ram_ptr, false, &offset);
    if (!block) {
        return panda_virt_to_phys(cpu, addr);
    } else {
        assert(block->mr);
        return block->mr->addr + offset;
    }
}

// These are used in softmmu_template.h
// ram_ptr is a possible pointer into host memory from the TLB code. Can be NULL.
void PCB(mem_before_read)(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                          size_t data_size, void *ram_ptr) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_VIRT_MEM_BEFORE_READ]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.virt_mem_before_read(env, env->panda_guest_pc, addr,
                                                              data_size);
    }
    if (panda_cbs[PANDA_CB_PHYS_MEM_BEFORE_READ]) {
        hwaddr paddr = get_paddr(env, addr, ram_ptr);
        for(plist = panda_cbs[PANDA_CB_PHYS_MEM_BEFORE_READ]; plist != NULL;
            plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.phys_mem_before_read(env, env->panda_guest_pc,
                                                                  paddr, data_size);
        }
    }
}


void PCB(mem_after_read)(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                         size_t data_size, uint64_t result, void *ram_ptr) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_VIRT_MEM_AFTER_READ]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        /* mstamat: Passing &result as the last cb arg doesn't make much sense. */
        if (plist->enabled) plist->entry.virt_mem_after_read(env, env->panda_guest_pc, addr,
                                         data_size, (uint8_t *)&result);
    }
    if (panda_cbs[PANDA_CB_PHYS_MEM_AFTER_READ]) {
        hwaddr paddr = get_paddr(env, addr, ram_ptr);
        for(plist = panda_cbs[PANDA_CB_PHYS_MEM_AFTER_READ]; plist != NULL;
            plist = panda_cb_list_next(plist)) {
            /* mstamat: Passing &result as the last cb arg doesn't make much sense. */
            if (plist->enabled) plist->entry.phys_mem_after_read(env, env->panda_guest_pc, paddr,
                                             data_size, (uint8_t *)&result);
        }
    }
}


void PCB(mem_before_write)(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                           size_t data_size, uint64_t val, void *ram_ptr) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_VIRT_MEM_BEFORE_WRITE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        /* mstamat: Passing &val as the last arg doesn't make much sense. */
        if (plist->enabled) plist->entry.virt_mem_before_write(env, env->panda_guest_pc, addr,
                                           data_size, (uint8_t *)&val);
    }
    if (panda_cbs[PANDA_CB_PHYS_MEM_BEFORE_WRITE]) {
        hwaddr paddr = get_paddr(env, addr, ram_ptr);
        for(plist = panda_cbs[PANDA_CB_PHYS_MEM_BEFORE_WRITE]; plist != NULL;
            plist = panda_cb_list_next(plist)) {
            /* mstamat: Passing &val as the last cb arg doesn't make much sense. */
            if (plist->enabled) plist->entry.phys_mem_before_write(env, env->panda_guest_pc, paddr,
                                               data_size, (uint8_t *)&val);
        }
    }
}


void PCB(mem_after_write)(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                          size_t data_size, uint64_t val, void *ram_ptr) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_VIRT_MEM_AFTER_WRITE]; plist != NULL;
         plist = panda_cb_list_next(plist)) {
        /* mstamat: Passing &val as the last cb arg doesn't make much sense. */
        if (plist->enabled) plist->entry.virt_mem_after_write(env, env->panda_guest_pc, addr,
                                          data_size, (uint8_t *)&val);
    }
    if (panda_cbs[PANDA_CB_PHYS_MEM_AFTER_WRITE]) {
        hwaddr paddr = get_paddr(env, addr, ram_ptr);
        for (plist = panda_cbs[PANDA_CB_PHYS_MEM_AFTER_WRITE]; plist != NULL;
             plist = panda_cb_list_next(plist)) {
            /* mstamat: Passing &val as the last cb arg doesn't make much sense. */
            if (plist->enabled) plist->entry.phys_mem_after_write(env, env->panda_guest_pc, paddr,
                                              data_size, (uint8_t *)&val);
        }
    }
}

// These are used in cputlb.c
void PCB(mmio_after_read)(CPUState *env, target_ptr_t addr, size_t size, uint64_t val) {

    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_MMIO_AFTER_READ]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.mmio_after_read(env, addr, size, val);
    }
}

void PCB(mmio_after_write)(CPUState *env, target_ptr_t addr, size_t size, uint64_t val) {

    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_MMIO_AFTER_WRITE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.mmio_after_write(env, addr, size, val);
    }
}

// vl.c
void PCB(after_machine_init)(CPUState *env) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_AFTER_MACHINE_INIT]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.after_machine_init(env);
    }
}

void PCB(during_machine_init)(MachineState *machine) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_DURING_MACHINE_INIT]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.during_machine_init(machine);
     }
}

void PCB(unassigned_io)(CPUState *env, hwaddr addr, size_t size,
       uint8_t *val, bool is_write) {
    if (is_write) {
        panda_cb_list *plist;
        for(plist = panda_cbs[PANDA_CB_UNASSIGNED_IO_WRITE]; plist != NULL;
            plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.unassigned_io_write(env, env->panda_guest_pc, addr, size, val);
        }
    }
    else {
        panda_cb_list *plist;
        for(plist = panda_cbs[PANDA_CB_UNASSIGNED_IO_READ]; plist != NULL;
            plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.unassigned_io_read(env, env->panda_guest_pc, addr, size, val);
        }
    }
}

void PCB(top_loop)(CPUState *env) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_TOP_LOOP]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.top_loop(env);
    }
}

// Returns 1 if any registered + enabled callback returns nonzero. If so, it doesn't let the asid change
int PCB(asid_changed)(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    panda_cb_list *plist;
    int any_nonzero = 0;
    for(plist = panda_cbs[PANDA_CB_ASID_CHANGED]; plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) {
            if (0 != plist->entry.asid_changed(env, old_asid, new_asid))  {
                //printf ("SOME asid_changed callback returned != 0\n");
                // Note we don't immediately return here because we allow all registered CBs to run
                any_nonzero = 1;
            }
        }
    }
    return any_nonzero;
}

// target-i386/misc_helpers.c
bool PCB(guest_hypercall)(CPUState *env) {
    int nprocessed = 0;
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_GUEST_HYPERCALL]; plist != NULL; plist = panda_cb_list_next(plist)) {
        if (plist->enabled) nprocessed += plist->entry.guest_hypercall(env);
    }
    if (nprocessed > 1) {
        LOG_WARNING("Hypercall processed by %d > 1 plugins.", nprocessed);
    }
    return nprocessed ? true : false;
}


void PCB(cpu_restore_state)(CPUState *env, TranslationBlock *tb) {
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_CPU_RESTORE_STATE]; plist != NULL;
        plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.cpu_restore_state(env, tb);
    }
}

void PCB(replay_serial_receive)(CPUState *cpu, target_ptr_t fifo_addr, uint8_t value)
{
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_SERIAL_RECEIVE]; plist != NULL;
             plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.replay_serial_receive(cpu, fifo_addr, value);
        }
    }
}

void PCB(replay_serial_read)(CPUState *cpu, target_ptr_t fifo_addr, uint32_t port_addr, uint8_t value)
{
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_SERIAL_READ]; plist != NULL;
             plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.replay_serial_read(cpu, fifo_addr, port_addr, value);
        }
    }
}

void PCB(replay_serial_send)(CPUState *cpu, target_ptr_t fifo_addr, uint8_t value)
{
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_SERIAL_SEND]; plist != NULL;
             plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.replay_serial_send(cpu, fifo_addr, value);
        }
    }
}

void PCB(replay_serial_write)(CPUState *cpu, target_ptr_t fifo_addr, uint32_t port_addr, uint8_t value)
{
    if (rr_in_replay()) {
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_REPLAY_SERIAL_WRITE]; plist != NULL;
             plist = panda_cb_list_next(plist)) {
            if (plist->enabled) plist->entry.replay_serial_write(cpu, fifo_addr, port_addr, value);
        }
    }
}

void PCB(main_loop_wait)(void) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_MAIN_LOOP_WAIT]; plist != NULL;
         plist = panda_cb_list_next(plist)) {
        if (plist->enabled) plist->entry.main_loop_wait();
    }

    if (panda_break_cpu_loop_req) {
        //       printf ("Clearing panda_break_cpu_loop_req\n");
        panda_break_cpu_loop_req = false;
    }
}

void PCB(pre_shutdown)(void) {
    panda_cb_list *plist;
    for (plist = panda_cbs[PANDA_CB_PRE_SHUTDOWN]; plist != NULL;
         plist = panda_cb_list_next(plist)) {
        plist->entry.pre_shutdown();
    }
}



// this callback allows us to swallow exceptions
// 
// first callback that returns an exception index that *differs* from
// the one passed as an arg wins. That is, that is what we return as
// the new exception index, which will replace cpu->exception_index
// 
// Note: We still run all of the callbacks, but only one of them can 
// change the current cpu exception.  Sorry.
// 
int32_t PCB(before_handle_exception)(CPUState *cpu, int32_t exception_index) {
    panda_cb_list *plist;
    bool got_new_exception = false;
    int32_t new_exception;

    for (plist = panda_cbs[PANDA_CB_BEFORE_HANDLE_EXCEPTION]; plist != NULL;
         plist = panda_cb_list_next(plist)) {
        if (plist->enabled) {
            int32_t new_e = plist->entry.before_handle_exception(cpu, exception_index);
            if (!got_new_exception && new_e != exception_index) {
                got_new_exception = true;
                new_exception = new_e;
            }
        }                
    }

    if (got_new_exception) 
        return new_exception;

    return exception_index;
}
