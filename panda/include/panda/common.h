/*!
 * @file panda/common.h
 * @brief Common PANDA utility functions.
 *
 * @note Functions that are both simple and frequently called are
 * defined here as inlines. Functions that are either complex or
 * infrequently called are decalred here and defined in `src/common.c`.
 */
#pragma once
#if !defined(__cplusplus)
#include <stdint.h>
#include <stdbool.h>
#else
#include <cstdint>
#include <cstdbool>
#endif
#include "cpu.h"
#include "exec/address-spaces.h"
#include "panda/types.h"

/**
 * @brief Branch predition hint macros.
 */
#if !defined(likely)
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#if !defined(unlikely)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * @brief Reads/writes data into/from \p buf from/to guest physical address \p addr.
 */
static inline int panda_physical_memory_rw(hwaddr addr, uint8_t *buf, int len,
                                           bool is_write) {
    hwaddr l = len;
    hwaddr addr1;
    MemoryRegion *mr = address_space_translate(&address_space_memory, addr,
                                               &addr1, &l, is_write);

    if (!memory_access_is_direct(mr, is_write)) {
        // fail for MMIO regions of physical address space
        return MEMTX_ERROR;
    }
    void *ram_ptr = qemu_map_ram_ptr(mr->ram_block, addr1);

    if (is_write) {
        memcpy(ram_ptr, buf, len);
    } else {
        memcpy(buf, ram_ptr, len);
    }
    return MEMTX_OK;
}

/**
 * @brief Translates guest virtual addres \p addr to a guest physical address.
 */
static inline hwaddr panda_virt_to_phys(CPUState *env, target_ulong addr) {
    target_ulong page;
    hwaddr phys_addr;
    page = addr & TARGET_PAGE_MASK;
    phys_addr = cpu_get_phys_page_debug(env, page);
    if (phys_addr == -1) {
        // no physical page mapped
        return -1;
    }
    phys_addr += (addr & ~TARGET_PAGE_MASK);
    return phys_addr;
}

/**
 * @brief Reads/writes data into/from \p buf from/to guest virtual address \p addr.
 */
static inline int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                                          uint8_t *buf, int len, bool is_write) {
    int l;
    int ret;
    hwaddr phys_addr;
    target_ulong page;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(env, page);
        if (phys_addr == -1) {
            // no physical page mapped
            return -1;
        }
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len) {
            l = len;
        }
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);
        if (ret != MEMTX_OK) {
            return ret;
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

/**
 * @brief Reads data into \p buf from guest virtual address \p addr.
 */
static inline int panda_virtual_memory_read(CPUState *env, target_ulong addr,
                                            uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 0);
}

/**
 * @brief Writes data from \p buf data to guest virtual address \p addr.
 */
static inline int panda_virtual_memory_write(CPUState *env, target_ulong addr,
                                             uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 1);
}

/**
 * @brief Determines if guest is currently executes in kernel mode.
 */
static inline bool panda_in_kernel(CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#elif defined(TARGET_PPC)
    return msr_pr;
#else
#error "panda_in_kernel() not implemented for target architecture."
    return false;
#endif
}

/**
 * @brief Returns the guest stack pointer.
 */
static inline target_ulong panda_current_sp(CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
    if (panda_in_kernel(cpu)) {
        // Return directly the ESP register value.
        return env->regs[R_ESP];
    } else {
        // Returned kernel ESP stored in the TSS.
        // Related reading: https://css.csail.mit.edu/6.858/2018/readings/i386/c07.htm
        const uint32_t esp0 = 4;
        const target_ulong tss_base = ((CPUX86State *)env)->tr.base + esp0;
        target_ulong kernel_esp = 0;
        if (panda_virtual_memory_rw(cpu, tss_base, (uint8_t *)&kernel_esp, sizeof(kernel_esp), false ) < 0) {
            return 0;
        }
        return kernel_esp;
    }
#elif defined(TARGET_ARM)
    // R13 on ARM.
    return env->regs[13];
#elif defined(TARGET_PPC)
    // R1 on PPC.
    return env->gpr[1];
#else
#error "panda_current_asid() not implemented for target architecture."
    return 0;
#endif
}


#ifdef __cplusplus
}
#endif

/* vim:set tabstop=4 softtabstop=4 expandtab: */
