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

// For each callback, use MAKE_CALLBACK or MAKE_REPLAY_ONLY_CALLBACK as defined in
#include "panda/callbacks/cb-macros.h"

#define PCB(name) panda_callbacks_ ## name

MAKE_REPLAY_ONLY_CALLBACK(REPLAY_HD_TRANSFER, replay_hd_transfer,
                    CPUState*, cpu, Hd_transfer_type, type,
                    target_ptr_t, src_addr, target_ptr_t, dest_addr,
                    size_t, num_bytes)

MAKE_REPLAY_ONLY_CALLBACK(REPLAY_NET_TRANSFER, replay_net_transfer,
                    CPUState*, cpu, Net_transfer_type, type,
                    uint64_t, src_addr, uint64_t, dst_addr,
                    size_t, num_bytes);

// TODO: rename callback
MAKE_CALLBACK(void, REPLAY_HANDLE_PACKET, replay_handle_packet,
                  CPUState*, cpu, uint8_t*, buf,
                  size_t, size, uint8_t, direction,
                  uint64_t, buf_addr_rec)


// These are used in exec.c
MAKE_REPLAY_ONLY_CALLBACK(REPLAY_BEFORE_DMA, replay_before_dma,
                    CPUState*, cpu, const uint8_t*, buf,
                    hwaddr, addr, size_t, size,
                    bool, is_write);

MAKE_REPLAY_ONLY_CALLBACK(REPLAY_AFTER_DMA, replay_after_dma,
                    CPUState*, cpu, const uint8_t*, buf,
                    hwaddr, addr, size_t ,size,
                    bool, is_write)

// These are used in cpu-exec.c
MAKE_CALLBACK(void, BEFORE_BLOCK_EXEC, before_block_exec,
                    CPUState*, cpu, TranslationBlock*, tb);

MAKE_CALLBACK(void, AFTER_BLOCK_EXEC, after_block_exec,
                    CPUState*, cpu, TranslationBlock*, tb,
                    uint8_t, exitCode);

MAKE_CALLBACK(void, BEFORE_BLOCK_TRANSLATE, before_block_translate,
                    CPUState*, cpu, target_ptr_t, pc);

MAKE_CALLBACK(void, AFTER_BLOCK_TRANSLATE, after_block_translate,
                    CPUState*, cpu, TranslationBlock*, tb);

MAKE_CALLBACK(void, AFTER_CPU_EXEC_ENTER, after_cpu_exec_enter,
                    CPUState*, cpu);

MAKE_CALLBACK(void, BEFORE_CPU_EXEC_EXIT, before_cpu_exec_exit,
                    CPUState*, cpu, bool, ranBlock);

MAKE_CALLBACK(void, AFTER_LOADVM, after_loadvm, CPUState*, env);

// These are used in target-i386/translate.c
MAKE_CALLBACK(bool, INSN_TRANSLATE, insn_translate,
                    CPUState*, env, target_ptr_t, pc);

MAKE_CALLBACK(bool, AFTER_INSN_TRANSLATE, after_insn_translate,
                    CPUState*, env, target_ptr_t, pc)

// Custom CB
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

// These are used in cputlb.c
MAKE_CALLBACK(void, MMIO_AFTER_READ, mmio_after_read,
                    CPUState*, env, target_ptr_t, physaddr,
                    target_ptr_t, vaddr, size_t, size,
                    uint64_t*, val);

MAKE_CALLBACK(void, MMIO_BEFORE_WRITE, mmio_before_write,
                    CPUState*, env, target_ptr_t, physaddr,
                    target_ptr_t, vaddr, size_t, size,
                    uint64_t*, val);

// vl.c
MAKE_CALLBACK(void, AFTER_MACHINE_INIT, after_machine_init,
                    CPUState*, env);

MAKE_CALLBACK(void, DURING_MACHINE_INIT, during_machine_init,
                    MachineState*, machine);

// Returns true if any registered&enabled callback returns non-zero.
// If so, we'll silence the memory write error.
MAKE_CALLBACK(bool, UNASSIGNED_IO_WRITE, unassigned_io_write,
                    CPUState*, env, target_ptr_t, pc,
                    hwaddr, addr, size_t, size,
                   uint64_t, val);

// Returns true if any registered&enabled callback returns non-zero,
// if so, we'll silence the invalid memory read error and return
// the value provided by the last callback in `val`
// Note if multiple callbacks run they can each mutate val
MAKE_CALLBACK(bool, UNASSIGNED_IO_READ, unassigned_io_read,
                    CPUState*, env, target_ptr_t, pc,
                    hwaddr, addr, size_t, size,
                   uint64_t*, val);

MAKE_CALLBACK(void, TOP_LOOP, top_loop,
                    CPUState*, cpu);

// Returns true if any registered + enabled callback returns nonzero.
// If so, it doesn't let the asid change
MAKE_CALLBACK(bool, ASID_CHANGED, asid_changed,
                    CPUState*, env, target_ulong, old_asid,
                    target_ulong, new_asid);


// target-i386/misc_helpers.c
MAKE_CALLBACK(bool, GUEST_HYPERCALL, guest_hypercall,
                    CPUState*, env);

MAKE_CALLBACK(void, CPU_RESTORE_STATE, cpu_restore_state,
                    CPUState*, env, TranslationBlock*, tb);

MAKE_REPLAY_ONLY_CALLBACK(REPLAY_SERIAL_RECEIVE, replay_serial_receive,
                    CPUState*, env, target_ptr_t, fifo_addr,
                    uint8_t, value);

MAKE_REPLAY_ONLY_CALLBACK(REPLAY_SERIAL_READ, replay_serial_read,
                    CPUState*, env, target_ptr_t, fifo_addr,
                    uint32_t, port_addr, uint8_t, value);

MAKE_REPLAY_ONLY_CALLBACK(REPLAY_SERIAL_SEND, replay_serial_send,
                    CPUState*, env, target_ptr_t, fifo_addr,
                    uint8_t, value);

MAKE_REPLAY_ONLY_CALLBACK(REPLAY_SERIAL_WRITE, replay_serial_write,
                    CPUState*, env, target_ptr_t, fifo_addr,
                    uint32_t, port_addr, uint8_t, value);

MAKE_CALLBACK(void, MAIN_LOOP_WAIT, main_loop_wait, void);

MAKE_CALLBACK(void, PRE_SHUTDOWN, pre_shutdown, void);


// Non-standard callbacks below here

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


// this callback allows us to swallow exceptions
//
// first callback that returns an exception index that *differs* from
// the one passed as an arg wins. That is, that is what we return as
// the new exception index, which will replace cpu->exception_index
//
// Note: We still run all of the callbacks, but only one of them can
// change the current cpu exception.  Sorry.

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

// These are used in softmmu_template.h. They are distinct from MAKE_CALLBACK's standard form.
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
