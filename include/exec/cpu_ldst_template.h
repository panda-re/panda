/*
 *  Software MMU support
 *
 * Generate inline load/store functions for one MMU mode and data
 * size.
 *
 * Generate a store function as well as signed and unsigned loads.
 *
 * Not used directly but included from cpu_ldst.h.
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

#if !defined(SOFTMMU_CODE_ACCESS)
#include "trace-root.h"
#endif

#include "trace/mem.h"

#if DATA_SIZE == 8
#define SUFFIX q
#define USUFFIX q
#define DATA_TYPE uint64_t
#define SHIFT 3
#elif DATA_SIZE == 4
#define SUFFIX l
#define USUFFIX l
#define DATA_TYPE uint32_t
#define SHIFT 2
#elif DATA_SIZE == 2
#define SUFFIX w
#define USUFFIX uw
#define DATA_TYPE uint16_t
#define DATA_STYPE int16_t
#define SHIFT 1
#elif DATA_SIZE == 1
#define SUFFIX b
#define USUFFIX ub
#define DATA_TYPE uint8_t
#define DATA_STYPE int8_t
#define SHIFT 0
#else
#error unsupported data size
#endif

#if DATA_SIZE == 8
#define RES_TYPE uint64_t
#else
#define RES_TYPE uint32_t
#endif

#ifdef SOFTMMU_CODE_ACCESS
#define ADDR_READ addr_code
#define MMUSUFFIX _cmmu
#define URETSUFFIX SUFFIX
#define SRETSUFFIX SUFFIX
#else
#define ADDR_READ addr_read
#define MMUSUFFIX _mmu
#define URETSUFFIX USUFFIX
#define SRETSUFFIX glue(s, SUFFIX)
#endif

#ifndef CONFIG_SOFTMMU_EXTERN_VAR_ONCE
#define CONFIG_SOFTMMU_EXTERN_VAR_ONCE
extern bool panda_use_memcb;
#endif

#ifndef MEM_CBS_REFERENCED
#define MEM_CBS_REFERENCED
#define target_ptr_t target_ulong
extern void panda_callbacks_mem_before_read(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t data_size, void *ram_ptr);
extern void panda_callbacks_mem_after_read(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t data_size, uint64_t result, void *ram_ptr);
extern void panda_callbacks_mem_before_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t data_size, uint64_t val, void *ram_ptr);
extern void panda_callbacks_mem_after_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t data_size, uint64_t val, void *ram_ptr);
#endif


/* generic load/store macros */

static inline RES_TYPE
glue(glue(glue(cpu_ld, USUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  target_ulong ptr,
                                                  uintptr_t retaddr)
{
    int page_index;
    RES_TYPE res;
    target_ulong addr;
    int mmu_idx;
    TCGMemOpIdx oi;

#if !defined(SOFTMMU_CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(SHIFT, false, MO_TE, false));
#endif

    addr = ptr;
    page_index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if (unlikely(env->tlb_table[mmu_idx][page_index].ADDR_READ !=
                 (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))))) {
        oi = make_memop_idx(SHIFT, mmu_idx);
        res = glue(glue(helper_ret_ld, URETSUFFIX), MMUSUFFIX)(env, addr,
                                                            oi, retaddr);
    } else {
        uintptr_t hostaddr = addr + env->tlb_table[mmu_idx][page_index].addend;
        #if defined(PANDA_DO_CBS_DATA_ACCESS)
        if (likely(!panda_use_memcb)){
            res = glue(glue(ld, USUFFIX), _p)((uint8_t *)hostaddr);
        }else{
            CPUState *cpu = ENV_GET_CPU(env);
            panda_callbacks_mem_before_read(cpu, cpu->panda_guest_pc, addr, DATA_SIZE, (void *)hostaddr);
            res = glue(glue(ld, USUFFIX), _p)((uint8_t *)hostaddr);
            panda_callbacks_mem_after_read(cpu, cpu->panda_guest_pc, addr, DATA_SIZE, (uint64_t)res, (void *)hostaddr);
        }
        #else
        res = glue(glue(ld, USUFFIX), _p)((uint8_t *)hostaddr);
        #endif
    }
    return res;
}

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr)
{
    return glue(glue(glue(cpu_ld, USUFFIX), MEMSUFFIX), _ra)(env, ptr, 0);
}

#if DATA_SIZE <= 2
static inline int
glue(glue(glue(cpu_lds, SUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  target_ulong ptr,
                                                  uintptr_t retaddr)
{
    int res, page_index;
    target_ulong addr;
    int mmu_idx;
    TCGMemOpIdx oi;

#if !defined(SOFTMMU_CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(SHIFT, true, MO_TE, false));
#endif

    addr = ptr;
    page_index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if (unlikely(env->tlb_table[mmu_idx][page_index].ADDR_READ !=
                 (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))))) {
        oi = make_memop_idx(SHIFT, mmu_idx);
        res = (DATA_STYPE)glue(glue(helper_ret_ld, SRETSUFFIX),
                               MMUSUFFIX)(env, addr, oi, retaddr);
    } else {
        uintptr_t hostaddr = addr + env->tlb_table[mmu_idx][page_index].addend;
        #if defined(PANDA_DO_CBS_DATA_ACCESS)
        if (likely(!panda_use_memcb)){
            res = glue(glue(lds, SUFFIX), _p)((uint8_t *)hostaddr);
        }else{
            CPUState *cpu = ENV_GET_CPU(env);
            panda_callbacks_mem_before_read(cpu, cpu->panda_guest_pc, addr, DATA_SIZE, (void *)hostaddr);
            res = glue(glue(lds, SUFFIX), _p)((uint8_t *)hostaddr);
            panda_callbacks_mem_after_read(cpu, cpu->panda_guest_pc, addr, DATA_SIZE, (uint64_t)res, (void *)hostaddr);
        }
        #else
        res = glue(glue(lds, SUFFIX), _p)((uint8_t *)hostaddr);
        #endif
    }
    return res;
}

static inline int
glue(glue(cpu_lds, SUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr)
{
    return glue(glue(glue(cpu_lds, SUFFIX), MEMSUFFIX), _ra)(env, ptr, 0);
}
#endif

#ifndef SOFTMMU_CODE_ACCESS

/* generic store macro */

static inline void
glue(glue(glue(cpu_st, SUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                 target_ulong ptr,
                                                 RES_TYPE v, uintptr_t retaddr)
{
    int page_index;
    target_ulong addr;
    int mmu_idx;
    TCGMemOpIdx oi;

#if !defined(SOFTMMU_CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(SHIFT, false, MO_TE, true));
#endif

    addr = ptr;
    page_index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if (unlikely(env->tlb_table[mmu_idx][page_index].addr_write !=
                 (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))))) {
        oi = make_memop_idx(SHIFT, mmu_idx);
        glue(glue(helper_ret_st, SUFFIX), MMUSUFFIX)(env, addr, v, oi,
                                                     retaddr);
    } else {
        uintptr_t hostaddr = addr + env->tlb_table[mmu_idx][page_index].addend;
        #if defined(PANDA_DO_CBS_DATA_ACCESS)
        if (likely(!panda_use_memcb)){
            glue(glue(st, SUFFIX), _p)((uint8_t *)hostaddr, v);
        }else{
            CPUState *cpu = ENV_GET_CPU(env);
            panda_callbacks_mem_before_write(cpu, cpu->panda_guest_pc, addr, DATA_SIZE, (uint64_t)v, (void *)hostaddr);
            glue(glue(st, SUFFIX), _p)((uint8_t *)hostaddr, v);
            panda_callbacks_mem_after_write(cpu, cpu->panda_guest_pc, addr, DATA_SIZE, (uint64_t)v, (void *)hostaddr);
        }
        #else
        glue(glue(st, SUFFIX), _p)((uint8_t *)hostaddr, v);
        #endif
    }
}

static inline void
glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr,
                                      RES_TYPE v)
{
    glue(glue(glue(cpu_st, SUFFIX), MEMSUFFIX), _ra)(env, ptr, v, 0);
}

#endif /* !SOFTMMU_CODE_ACCESS */

#undef RES_TYPE
#undef DATA_TYPE
#undef DATA_STYPE
#undef SUFFIX
#undef USUFFIX
#undef DATA_SIZE
#undef MMUSUFFIX
#undef ADDR_READ
#undef URETSUFFIX
#undef SRETSUFFIX
#undef SHIFT
