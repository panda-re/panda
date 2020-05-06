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

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

void panda_cleanup(void);
void panda_set_os_name(char *os_name);
void panda_before_find_fast(void);
void panda_disas(FILE *out, void *code, unsigned long size);
void panda_break_main_loop(void);
MemoryRegion* panda_find_ram(void);

extern bool panda_exit_loop;
extern bool panda_break_vl_loop_req;


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

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

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
 * @brief If required for the target architecture, enter into a high-privilege mode in
 * order to conduct some memory access. Returns true if a switch into high-privilege
 * mode has been made. A NO-OP on systems where such changes are unnecessary.
 */
bool enter_priv(CPUState* cpu);

/**
 * @brief Revert the guest to the privilege mode it was in prior to the last call
 * to enter_priv(). A NO-OP for architectures where enter_prov is a NO-OP.
 */
void exit_priv(CPUState* cpu);


/**
 * @brief Reads/writes data into/from \p buf from/to guest virtual address \p addr.
 *
 * For ARM we switch CPSR into SVC (privileged) mode if the access fails. The mode is always reset
 * before we return.
 */
static inline int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                                          uint8_t *buf, int len, bool is_write) {
    int l;
    int ret;
    hwaddr phys_addr;
    target_ulong page;
    bool changed_priv = false;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(env, page);
        // If we failed and we aren't in priv mode and we CAN go into it, toggle modes and try again
        if (phys_addr == -1  && !changed_priv && (changed_priv=enter_priv(env))) {
            phys_addr = cpu_get_phys_page_debug(env, page);
            //if (phys_addr != -1) printf("[panda dbg] virt->phys failed until privileged mode\n");
        }

        // No physical page mapped, even after potential privileged switch, abort
        if (phys_addr == -1)  {
            if (changed_priv) exit_priv(env); // Cleanup mode if necessary
            return -1;
        }

        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len) {
            l = len;
        }
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);

        // Failed and privileged mode wasn't already enabled - enable priv and retry if we can
        if (ret != MEMTX_OK && !changed_priv && (changed_priv = enter_priv(env))) {
            ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);
            //if (ret == MEMTX_OK) printf("[panda dbg] accessing phys failed until privileged mode\n");
        }
        // Still failed, even after potential privileged switch, abort
        if (ret != MEMTX_OK) {
            if (changed_priv) exit_priv(env); // Cleanup mode if necessary
            return ret;
        }

        len -= l;
        buf += l;
        addr += l;
    }
    if (changed_priv) exit_priv(env); // Clear privileged mode if necessary
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
 * @brief Obtains a host pointer for the given virtual address.
 */
static inline void *panda_map_virt_to_host(CPUState *env, target_ulong addr,
                                           int len)
{
    hwaddr phys = panda_virt_to_phys(env, addr);
    hwaddr l = len;
    hwaddr addr1;
    MemoryRegion *mr =
        address_space_translate(&address_space_memory, phys, &addr1, &l, true);

    if (!memory_access_is_direct(mr, true)) {
        return NULL;
    }

    return qemu_map_ram_ptr(mr->ram_block, addr1);
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
#error "panda_current_sp() not implemented for target architecture."
    return 0;
#endif
}

/**
 * @brief Returns the return value of the guest.
 * The function is only meant to provide a platform-independent
 * abstraction for retrieving a call return value. It still has to
 * be used in the proper context to retrieve a meaningful value.
 */
static inline target_ulong panda_get_retval(CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
    // EAX for x86.
    return env->regs[R_EAX];
#elif defined(TARGET_ARM)
    // R0 on ARM.
    return env->regs[0];
#elif defined(TARGET_PPC)
    // R3 on PPC.
    return env->gpr[3];
#else
#error "panda_get_retval() not implemented for target architecture."
    return 0;
#endif
}

#ifdef __cplusplus
}
#endif

/* vim:set tabstop=4 softtabstop=4 expandtab: */
