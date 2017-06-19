/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The file was modified for S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 *
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "trace-root.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/log.h"
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
#include "hw/i386/apic.h"
#endif
#include "sysemu/replay.h"
#include "panda/rr/rr_log.h"
#include "panda/callback_support.h"
#include "panda/common.h"

#ifdef CONFIG_LLVM
#include "panda/tcg-llvm.h"
const int has_llvm_engine = 1;
#endif

int generate_llvm = 0;
int execute_llvm = 0;

/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

#if !defined(CONFIG_USER_ONLY)
/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100

// Needed to prevent before_block_exec_invalidate_opt from 
// running more than once
bool panda_bb_invalidate_done = false;

static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
    int64_t cpu_icount;

    if (!icount_align_option) {
        return;
    }

    cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    sc->diff_clk += cpu_icount_to_ns(sc->last_cpu_icount - cpu_icount);
    sc->last_cpu_icount = cpu_icount;

    if (sc->diff_clk > VM_CLOCK_ADVANCE) {
#ifndef _WIN32
        struct timespec sleep_delay, rem_delay;
        sleep_delay.tv_sec = sc->diff_clk / 1000000000LL;
        sleep_delay.tv_nsec = sc->diff_clk % 1000000000LL;
        if (nanosleep(&sleep_delay, &rem_delay) < 0) {
            sc->diff_clk = rem_delay.tv_sec * 1000000000LL + rem_delay.tv_nsec;
        } else {
            sc->diff_clk = 0;
        }
#else
        Sleep(sc->diff_clk / SCALE_MS);
        sc->diff_clk = 0;
#endif
    }
}

static void print_delay(const SyncClocks *sc)
{
    static float threshold_delay;
    static int64_t last_realtime_clock;
    static int nb_prints;

    if (icount_align_option &&
        sc->realtime_clock - last_realtime_clock >= MAX_DELAY_PRINT_RATE &&
        nb_prints < MAX_NB_PRINTS) {
        if ((-sc->diff_clk / (float)1000000000LL > threshold_delay) ||
            (-sc->diff_clk / (float)1000000000LL <
             (threshold_delay - THRESHOLD_REDUCE))) {
            threshold_delay = (-sc->diff_clk / 1000000000LL) + 1;
            printf("Warning: The guest is now late by %.1f to %.1f seconds\n",
                   threshold_delay - 1,
                   threshold_delay);
            nb_prints++;
            last_realtime_clock = sc->realtime_clock;
        }
    }
}

static void init_delay_params(SyncClocks *sc,
                              const CPUState *cpu)
{
    if (!icount_align_option) {
        return;
    }
    sc->realtime_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    sc->diff_clk = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - sc->realtime_clock;
    sc->last_cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    if (sc->diff_clk < max_delay) {
        max_delay = sc->diff_clk;
    }
    if (sc->diff_clk > max_advance) {
        max_advance = sc->diff_clk;
    }

    /* Print every 2s max if the guest is late. We limit the number
       of printed messages to NB_PRINT_MAX(currently 100) */
    print_delay(sc);
}
#else
static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
}

static void init_delay_params(SyncClocks *sc, const CPUState *cpu)
{
}
#endif /* CONFIG USER ONLY */

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc_ptr;

    qemu_log_mask_and_addr(CPU_LOG_EXEC, itb->pc,
                           "Trace %p [%d: " TARGET_FMT_lx "] %s\n",
                           itb->tc_ptr, cpu->cpu_index, itb->pc,
                           lookup_symbol(itb->pc));

#if defined(DEBUG_DISAS)
    if (qemu_loglevel_mask(CPU_LOG_TB_CPU)
        && qemu_log_in_addr_range(itb->pc)) {
        qemu_log_lock();
#if defined(TARGET_I386)
        log_cpu_state(cpu, CPU_DUMP_CCOP);
#else
        log_cpu_state(cpu, 0);
#endif
        qemu_log_unlock();
    }
#endif /* DEBUG_DISAS */

    cpu->can_do_io = !use_icount;

    panda_callbacks_before_block_exec(cpu, itb);

    // NB: This is where we did this in panda1
    panda_bb_invalidate_done = false;

#if defined(CONFIG_LLVM)
    if (execute_llvm){
        assert(itb->llvm_tc_ptr);
        //next_tb = tcg_llvm_qemu_tb_exec(env, tb);
        ret = tcg_llvm_qemu_tb_exec(env, itb);
    } else {
        assert(tb_ptr);
        ret = tcg_qemu_tb_exec(env, tb_ptr);
    }
#else
    ret = tcg_qemu_tb_exec(env, tb_ptr);
#endif // CONFIG_LLVM

    cpu->can_do_io = 1;
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);

    panda_callbacks_after_block_exec(cpu, itb);

    tb_exit = ret & TB_EXIT_MASK;
    trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        qemu_log_mask_and_addr(CPU_LOG_EXEC, last_tb->pc,
                               "Stopped execution of TB chain before %p ["
                               TARGET_FMT_lx "] %s\n",
                               last_tb->tc_ptr, last_tb->pc,
                               lookup_symbol(last_tb->pc));
        if (cc->synchronize_from_tb) {
            cc->synchronize_from_tb(cpu, last_tb);
        } else {
            assert(cc->set_pc);
            cc->set_pc(cpu, last_tb->pc);
        }
    }
    if (tb_exit == TB_EXIT_REQUESTED) {
        /* We were asked to stop executing TBs (probably a pending
         * interrupt. We've now stopped, so clear the flag.
         */
        atomic_set(&cpu->tcg_exit_req, 0);
    }
    return ret;
}

#ifndef CONFIG_USER_ONLY
/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *cpu, int max_cycles,
                             TranslationBlock *orig_tb, bool ignore_icount)
{
    TranslationBlock *tb;

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    if (max_cycles > CF_COUNT_MASK)
        max_cycles = CF_COUNT_MASK;

    tb_lock();
    tb = tb_gen_code(cpu, orig_tb->pc, orig_tb->cs_base, orig_tb->flags,
                     max_cycles | CF_NOCACHE
                         | (ignore_icount ? CF_IGNORE_ICOUNT : 0));
    tb->orig_tb = orig_tb;
    tb_unlock();

    /* execute the generated code */
    trace_exec_tb_nocache(tb, tb->pc);
    cpu_tb_exec(cpu, tb);

    tb_lock();
    tb_phys_invalidate(tb, -1);
    tb_free(tb);
    tb_unlock();
}
#endif

static void cpu_exec_step(CPUState *cpu)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = tb_gen_code(cpu, pc, cs_base, flags,
                     1 | CF_NOCACHE | CF_IGNORE_ICOUNT);
    tb->orig_tb = NULL;
    /* execute the generated code */
    trace_exec_tb_nocache(tb, pc);
    cpu_tb_exec(cpu, tb);
    tb_phys_invalidate(tb, -1);
    tb_free(tb);
}

void cpu_exec_step_atomic(CPUState *cpu)
{
    start_exclusive();

    /* Since we got here, we know that parallel_cpus must be true.  */
    parallel_cpus = false;
    cpu_exec_step(cpu);
    parallel_cpus = true;

    end_exclusive();
}

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t phys_page1;
    uint32_t flags;
};

static bool tb_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if (tb->pc == desc->pc &&
        tb->page_addr[0] == desc->phys_page1 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags &&
        !atomic_read(&tb->invalid)) {
        /* check next page if needed */
        if (tb->page_addr[1] == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page2;
            target_ulong virt_page2;

            virt_page2 = (desc->pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
            phys_page2 = get_page_addr_code(desc->env, virt_page2);
            if (tb->page_addr[1] == phys_page2) {
                return true;
            }
        }
    }
    return false;
}

static TranslationBlock *tb_htable_lookup(CPUState *cpu,
                                          target_ulong pc,
                                          target_ulong cs_base,
                                          uint32_t flags)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = (CPUArchState *)cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    desc.phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_hash_func(phys_pc, pc, flags);
    return qht_lookup(&tcg_ctx.tb_ctx.htable, tb_cmp, &desc, h);
}

static inline TranslationBlock *tb_find(CPUState *cpu,
                                        TranslationBlock *last_tb,
                                        int tb_exit)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;
    bool have_tb_lock = false;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = atomic_rcu_read(&cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)]);
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                 tb->flags != flags)) {
        tb = tb_htable_lookup(cpu, pc, cs_base, flags);
        if (!tb) {

            /* mmap_lock is needed by tb_gen_code, and mmap_lock must be
             * taken outside tb_lock. As system emulation is currently
             * single threaded the locks are NOPs.
             */
            mmap_lock();
            tb_lock();
            have_tb_lock = true;

            /* There's a chance that our desired tb has been translated while
             * taking the locks so we check again inside the lock.
             */
            tb = tb_htable_lookup(cpu, pc, cs_base, flags);
            if (!tb) {
                panda_callbacks_before_block_translate(cpu, pc);

                /* if no translated code available, then translate it now */
                tb = tb_gen_code(cpu, pc, cs_base, flags, 0);

                panda_callbacks_after_block_translate(cpu, tb);
            }

            mmap_unlock();
        }

        /* We add the TB in the virtual pc hash table for the fast lookup */
        atomic_set(&cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)], tb);
    }
#ifndef CONFIG_USER_ONLY
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        last_tb = NULL;
    }
#endif
    /* See if we can patch the calling TB. */
#ifdef CONFIG_SOFTMMU
    if (rr_mode != RR_REPLAY /* && panda_tb_chaining */) {
#endif
    if (last_tb && !qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        if (!have_tb_lock) {
            tb_lock();
            have_tb_lock = true;
        }
        if (!tb->invalid) {
            tb_add_jump(last_tb, tb_exit, tb);
        }
    }
#ifdef CONFIG_SOFTMMU
    }
#endif
    if (have_tb_lock) {
        tb_unlock();
    }
    return tb;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
        if ((cpu->interrupt_request & CPU_INTERRUPT_POLL)
            && replay_interrupt()) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            apic_poll_irq(x86_cpu->apic_state);
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_POLL);
        }
#endif
        if (!cpu_has_work(cpu) && !rr_in_replay()) {
            current_cpu = NULL;
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    if (cpu->exception_index >= 0) {
        if (cpu->exception_index >= EXCP_INTERRUPT) {
            /* exit request from the cpu execution loop */
            *ret = cpu->exception_index;
            if (*ret == EXCP_DEBUG) {
                cpu_handle_debug_exception(cpu);
            }
            cpu->exception_index = -1;
            return true;
        } else {
#if defined(CONFIG_USER_ONLY)
            /* if user mode only, we simulate a fake exception
               which will be handled outside the cpu execution
               loop */
#if defined(TARGET_I386)
            CPUClass *cc = CPU_GET_CLASS(cpu);
            cc->do_interrupt(cpu);
#endif
            *ret = cpu->exception_index;
            cpu->exception_index = -1;
            return true;
#else
            if (replay_exception()) {

#ifdef CONFIG_SOFTMMU
                int32_t excp_index; 
                RR_DO_RECORD_OR_REPLAY(
                    excp_index = cpu->exception_index;,
                    rr_record_exception(RR_CALLSITE_CPU_EXCEPTION_INDEX, excp_index);,
                    rr_replay_exception((int32_t*)&cpu->exception_index);,
                    RR_CALLSITE_CPU_EXCEPTION_INDEX);
#endif
                CPUClass *cc = CPU_GET_CLASS(cpu);
                cc->do_interrupt(cpu);
                cpu->exception_index = -1;
            } else if (!replay_has_interrupt()) {
                /* give a chance to iothread in replay mode */
                *ret = EXCP_INTERRUPT;
                return true;
            }
#endif
        }
#ifndef CONFIG_USER_ONLY
    } else if (replay_has_exception()
               && cpu->icount_decr.u16.low + cpu->icount_extra == 0) {
        /* try to cause an exception pending in the log */
        cpu_exec_nocache(cpu, 1, tb_find(cpu, NULL, 0), true);
        *ret = -1;
        return true;
#endif
    }

    return false;
}

static inline void cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int interrupt_request = cpu->interrupt_request;
#ifdef CONFIG_SOFTMMU
    //mz Record and Replay.
    //mz it is important to do this in the order written, as
    //during record env->interrupt_request can be changed at any
    //time via a signal.  Thus, we want to make sure that we
    //record the same value in the log as the one being used in
    //these decisions.
    rr_skipped_callsite_location = RR_CALLSITE_CPU_HANDLE_INTERRUPT_BEFORE;
    rr_interrupt_request(&interrupt_request);

    if (rr_in_replay()) {
        cpu->interrupt_request = interrupt_request;
    }
#endif
    if (unlikely(interrupt_request)) {
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            cpu_loop_exit(cpu);
        }
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        } else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            cpu_loop_exit(cpu);
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            cpu_loop_exit(cpu);
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            cpu_loop_exit(cpu);
        }
#endif
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                replay_interrupt();
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
#ifdef CONFIG_SOFTMMU
        //mz record the value again in case do_interrupt has set EXITTB flag
        rr_skipped_callsite_location = RR_CALLSITE_CPU_HANDLE_INTERRUPT_AFTER;
        rr_interrupt_request((int *)&cpu->interrupt_request);
        if (rr_in_replay()) {
            interrupt_request = cpu->interrupt_request;
        }
#endif
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }
    }
    if (unlikely(atomic_read(&cpu->exit_request) || replay_has_interrupt())) {
        atomic_set(&cpu->exit_request, 0);
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit,
                                    SyncClocks *sc)
{
    uintptr_t ret;

    if (unlikely(atomic_read(&cpu->exit_request))) {
        return;
    }

    trace_exec_tb(tb, tb->pc);
    ret = cpu_tb_exec(cpu, tb);
    *last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    *tb_exit = ret & TB_EXIT_MASK;
    switch (*tb_exit) {
    case TB_EXIT_REQUESTED:
        /* Something asked us to stop executing
         * chained TBs; just continue round the main
         * loop. Whatever requested the exit will also
         * have set something else (eg exit_request or
         * interrupt_request) which we will handle
         * next time around the loop.  But we need to
         * ensure the tcg_exit_req read in generated code
         * comes before the next read of cpu->exit_request
         * or cpu->interrupt_request.
         */
        smp_rmb();
        *last_tb = NULL;
        break;
    case TB_EXIT_ICOUNT_EXPIRED:
    {
        /* Instruction counter expired.  */
#ifdef CONFIG_USER_ONLY
        abort();
#else
        int insns_left = cpu->icount_decr.u32;
        if (cpu->icount_extra && insns_left >= 0) {
            /* Refill decrementer and continue execution.  */
            cpu->icount_extra += insns_left;
            insns_left = MIN(0xffff, cpu->icount_extra);
            cpu->icount_extra -= insns_left;
            cpu->icount_decr.u16.low = insns_left;
        } else {
            if (insns_left > 0) {
                /* Execute remaining instructions.  */
                cpu_exec_nocache(cpu, insns_left, *last_tb, false);
                align_clocks(sc, cpu);
            }
            cpu->exception_index = EXCP_INTERRUPT;
            *last_tb = NULL;
            cpu_loop_exit(cpu);
        }
        break;
#endif
    }
    default:
        break;
    }
}

#ifdef CONFIG_DEBUG_TCG
uint64_t counter_128k = 0;
void debug_counter(void);
void debug_counter(void) {
    counter_128k++;
}
#endif
__attribute__((always_inline))
inline void debug_checkpoint(CPUState *cpu);
__attribute__((always_inline))
inline void debug_checkpoint(CPUState *cpu) {
#ifdef CONFIG_DEBUG_TCG
    if (rr_mode != RR_OFF
            && cpu->rr_guest_instr_count >> 17 > counter_128k) {
        debug_counter();
    }
#endif
}

/* main execution loop */

int cpu_exec(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc;

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

#ifdef CONFIG_SOFTMMU
    //mz This is done once at the start of record and once at the start of
    //replay.  So we should be ok.
    if (unlikely(rr_flush_tb())) {
        qemu_log_mask(CPU_LOG_RR, "flushing tb\n");
        tb_flush(cpu);
        rr_flush_tb_off();  // just the first time, eh?
    }
#endif
    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    atomic_mb_set(&tcg_current_cpu, cpu);
    rcu_read_lock();

    if (unlikely(atomic_mb_read(&exit_request))) {
        cpu->exit_request = 1;
    }

    cc->cpu_exec_enter(cpu);

    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);

    for(;;) {
        /* prepare setjmp context for exception handling */
        if (sigsetjmp(cpu->jmp_env, 0) == 0) {
            TranslationBlock *tb, *last_tb = NULL;
            int tb_exit = 0;

            /* if an exception is pending, we execute it here */
            if (cpu_handle_exception(cpu, &ret)) {
                break;
            }

            for(;;) {
                bool panda_invalidate_tb = false;
                debug_checkpoint(cpu);
                //bdg Replay skipped calls from the I/O thread here
                if (rr_in_replay()) {
                    rr_skipped_callsite_location = RR_CALLSITE_MAIN_LOOP_WAIT;
                    rr_replay_skipped_calls();
                }
                cpu_handle_interrupt(cpu, &last_tb);
                panda_before_find_fast();
                tb = tb_find(cpu, last_tb, tb_exit);
                panda_bb_invalidate_done = panda_callbacks_after_find_fast(
                        cpu, tb, panda_bb_invalidate_done, &panda_invalidate_tb);
                if (qemu_loglevel_mask(CPU_LOG_RR)) {
                    RR_prog_point pp = rr_prog_point();
                    qemu_log_mask(CPU_LOG_RR,
                            "Prog point: 0x" TARGET_FMT_lx " {guest_instr_count=%llu}\n",
                            tb->pc, (unsigned long long)pp.guest_instr_count);
                }

#ifdef CONFIG_SOFTMMU
                uint64_t until_interrupt = rr_num_instr_before_next_interrupt();
                if (panda_invalidate_tb
                        || (rr_mode == RR_REPLAY && until_interrupt > 0
                            && tb->icount > until_interrupt)) {
                    // retranslate so that basic block boundary matches
                    // record & replay for interrupt delivery
                    tb_flush(cpu);
                    tb = tb_find(cpu, last_tb, tb_exit);
                }
#endif //CONFIG_SOFTMMU
                // Check for termination in replay
                if (rr_mode == RR_REPLAY && rr_replay_finished()) {
                    rr_do_end_replay(0);
                    qemu_cpu_kick(cpu);
                    break;
                }
                if (!rr_in_replay() || until_interrupt > 0) {
                    cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit, &sc);
                    /* Try to align the host and virtual clocks
                       if the guest is in advance */
                    align_clocks(&sc, cpu);
                }
            } /* for(;;) */
        } else {
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
            /* Some compilers wrongly smash all local variables after
             * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
             * Reload essential local variables here for those compilers.
             * Newer versions of gcc would complain about this code (-Wclobbered). */
            cpu = current_cpu;
            cc = CPU_GET_CLASS(cpu);
#else /* buggy compiler */
            /* Assert that the compiler does not smash local variables. */
            g_assert(cpu == current_cpu);
            g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */
            cpu->can_do_io = 1;
            tb_lock_reset();
        }
    } /* for(;;) */

    cc->cpu_exec_exit(cpu);
    rcu_read_unlock();

    /* fail safe : never use current_cpu outside cpu_exec() */
    current_cpu = NULL;

    /* Does not need atomic_mb_set because a spurious wakeup is okay.  */
    atomic_set(&tcg_current_cpu, NULL);
    return ret;
}
