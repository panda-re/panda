/*
 *  Host code generation
 *
 *  Copyright (c) 2003 Fabrice Bellard
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "config.h"

#define NO_CPU_IO_DEFS
#include "cpu.h"
#include "disas.h"
#include "tcg.h"
#include "qemu-timer.h"

#ifdef CONFIG_LLVM
#include "tcg-llvm.h"
#endif

#include "panda_plugin.h"

/* code generation context */
TCGContext tcg_ctx;

uint16_t gen_opc_buf[OPC_BUF_SIZE];
TCGArg gen_opparam_buf[OPPARAM_BUF_SIZE];

target_ulong gen_opc_pc[OPC_BUF_SIZE];
uint16_t gen_opc_icount[OPC_BUF_SIZE];
uint8_t gen_opc_instr_start[OPC_BUF_SIZE];

void cpu_gen_init(void)
{
    tcg_context_init(&tcg_ctx); 
}

/* return non zero if the very first instruction is invalid so that
   the virtual CPU can trigger an exception.

   '*gen_code_size_ptr' contains the size of the generated code (host
   code).
*/
int cpu_gen_code(CPUState *env, TranslationBlock *tb, int *gen_code_size_ptr)
{
    TCGContext *s = &tcg_ctx;
    uint8_t *gen_code_buf;
    int gen_code_size;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count1++; /* includes aborted translations because of
                       exceptions */
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    gen_intermediate_code(env, tb);

    /* generate machine code */
    gen_code_buf = tb->tc_ptr;
    tb->tb_next_offset[0] = 0xffff;
    tb->tb_next_offset[1] = 0xffff;
    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count++;
    s->interm_time += profile_getclock() - ti;
    s->code_time -= profile_getclock();
#endif
    gen_code_size = tcg_gen_code(s, gen_code_buf);
    *gen_code_size_ptr = gen_code_size;

#if defined(CONFIG_LLVM)
    if(generate_llvm)
        tcg_llvm_gen_code(tcg_llvm_ctx, s, tb);
#endif

#ifdef CONFIG_PROFILER
    s->code_time += profile_getclock();
    s->code_in_len += tb->size;
    s->code_out_len += gen_code_size;
#endif

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM)) {
        qemu_log("OUT: [size=%d]\n", *gen_code_size_ptr);
        log_disas(tb->tc_ptr, *gen_code_size_ptr);
        qemu_log("\n");
        qemu_log_flush();
    }

#if defined(CONFIG_LLVM)
    if(generate_llvm && qemu_loglevel_mask(CPU_LOG_LLVM_ASM)
            && tb->llvm_tc_ptr) {
        ptrdiff_t size = tb->llvm_tc_end - tb->llvm_tc_ptr;
        qemu_log("OUT (LLVM ASM) [size=%ld] (%s)\n", size,
                    tcg_llvm_get_func_name(tb));
        log_disas((void*) tb->llvm_tc_ptr, size);
        qemu_log("\n");
        qemu_log_flush();
    }
#endif

#endif
    return 0;
}

/* The cpu state corresponding to 'searched_pc' is restored.
 */
int cpu_restore_state(TranslationBlock *tb,
                      CPUState *env, unsigned long searched_pc)
{
    // PANDA instrumentation: CPU restore state
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_CPU_RESTORE_STATE]; plist != NULL;
            plist = plist->next) {
        plist->entry.cb_cpu_restore_state(env, tb);
    }
 
    TCGContext *s = &tcg_ctx;
    int j;
    unsigned long tc_ptr;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    gen_intermediate_code_pc(env, tb);

    if (use_icount) {
        /* Reset the cycle counter to the start of the block.  */
        env->icount_decr.u16.low += tb->icount;
        /* Clear the IO flag.  */
        env->can_do_io = 0;
    }

#if defined(CONFIG_LLVM)
    if(execute_llvm) {
        assert(tb->llvm_function != NULL);
        j = tcg_llvm_search_last_pc(tb, searched_pc);
    } else {
#endif

    /* find opc index corresponding to search_pc */
    tc_ptr = (unsigned long)tb->tc_ptr;
    if (searched_pc < tc_ptr)
        return -1;

    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif
    j = tcg_gen_code_search_pc(s, (uint8_t *)tc_ptr, searched_pc - tc_ptr);

#ifdef CONFIG_LLVM
    }
#endif
    if (j < 0)
        return -1;
    /* now find start of instruction before */
    while (gen_opc_instr_start[j] == 0)
        j--;


    env->icount_decr.u16.low -= gen_opc_icount[j];

    restore_state_to_opc(env, tb, j);

#ifdef CONFIG_PROFILER
    s->restore_time += profile_getclock() - ti;
    s->restore_count++;
#endif
    return 0;
}
