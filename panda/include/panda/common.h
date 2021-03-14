/*!
 * @file panda/common.h
 * @brief Common PANDA utility functions.
 *
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
#include "panda/plugin_api.h" // Just including it form somewhere for now

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

#if defined(TARGET_MIPS)
#define MIPS_HFLAG_KSU    0x00003 /* kernel/supervisor/user mode mask   */
#define MIPS_HFLAG_KM     0x00000 /* kernel mode flag                   */
/**
 *  Register values from: http://www.cs.uwm.edu/classes/cs315/Bacon/Lecture/HTML/ch05s03.html
 */
#define MIPS_SP           29      /* value for MIPS stack pointer offset into GPR */
#define MIPS_V0           2
#define MIPS_V1           3
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

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

/**
 * @brief Reads/writes data into/from \p buf from/to guest physical address \p addr.
 */

int panda_physical_memory_rw(hwaddr addr, uint8_t *buf, int len,
                                           bool is_write);

/**
 * @brief Translates guest virtual addres \p addr to a guest physical address.
 */
hwaddr panda_virt_to_phys(CPUState *env, target_ulong addr);

/**
 * @brief If required for the target architecture, enter into a high-privilege mode in
 * order to conduct some memory access. Returns true if a switch into high-privilege
 * mode has been made. A NO-OP on systems where such changes are unnecessary.
 */
bool enter_priv(CPUState* cpu);

/**
 * @brief Revert the guest to the privilege mode it was in prior to the last call
 * to enter_priv(). A NO-OP for architectures where enter_priv() is a NO-OP.
 */
void exit_priv(CPUState* cpu);


/**
 * @brief Reads/writes data into/from \p buf from/to guest virtual address \p addr.
 *
 * For ARM/MIPS we switch into privileged mode if the access fails. The mode is always reset
 * before we return.
 */
int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                                          uint8_t *buf, int len, bool is_write);
/**
 * @brief Reads data into \p buf from guest virtual address \p addr.
 */
int panda_virtual_memory_read(CPUState *env, target_ulong addr,
                                            uint8_t *buf, int len);

/**
 * @brief Writes data from \p buf data to guest virtual address \p addr.
 */
int panda_virtual_memory_write(CPUState *env, target_ulong addr,
                                             uint8_t *buf, int len);

/**
 * @brief Obtains a host pointer for the given virtual address.
 */
void *panda_map_virt_to_host(CPUState *env, target_ulong addr,
                                           int len);

/**
 * @brief Translate a physical address to a RAM Offset (needed for the taint system)
 * Returns MEMTX_OK on success.
 */
MemTxResult PandaPhysicalAddressToRamOffset(ram_addr_t* out, hwaddr addr, bool is_write);

/**
 * @brief Translate a virtual address to a RAM Offset (needed for the taint system)
 * Returns MEMTX_OK on success.
 */
MemTxResult PandaVirtualAddressToRamOffset(ram_addr_t* out, CPUState* cpu, target_ulong addr, bool is_write);

/**
 * @brief Determines if guest is currently executes in kernel mode.
 */
bool panda_in_kernel(const CPUState *cpu);
/**
 * @brief Returns the guest kernel stack pointer.
 */
target_ulong panda_current_ksp(CPUState *cpu);

/**
 * @brief Returns the guest stack pointer.
 */
target_ulong panda_current_sp(const CPUState *cpu);

/**
 * @brief Returns the return value of the guest.
 * The function is only meant to provide a platform-independent
 * abstraction for retrieving a call return value. It still has to
 * be used in the proper context to retrieve a meaningful value.
 */
target_ulong panda_get_retval(const CPUState *cpu);

#ifdef __cplusplus
}
#endif

/* vim:set tabstop=4 softtabstop=4 expandtab: */
