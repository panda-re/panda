/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

/*
 * DECAF_main.h
 *
 *  Created on: Oct 14, 2012
 *      Author: lok
 *  This is half of the old main.h. All of the declarations here are
 *  target independent. All of the target dependent declarations and code
 *  are in the target directory in DECAF_main_x86.h and .c for example
 */

#ifndef DECAF_MAIN_H_
#define DECAF_MAIN_H_

#include "qemu-common.h"
#include "monitor.h"
#include "cpu-defs.h"
#include "DECAF_shared/DECAF_config.h"
#include "DECAF_shared/DECAF_types.h"
#include "blockdev.h"

#ifdef __cplusplus
extern "C"
{
#endif


/*************************************************************************
 * The Plugin interface comes first
 *************************************************************************/


/// primary structure for DECAF plugin,
// callbacks have been removed due to the new interface
// including callbacks and states
// tainting has also been removed since we are going to
// have a new tainting interface that is dynamically
// controllable - which will be more like a util than
// something that is built directly into DECAF
typedef struct _plugin_interface {
  /// array of monitor commands
  const mon_cmd_t *mon_cmds; // AWH - was term_cmd_t *term_cmds
  /// array of informational commands
  const mon_cmd_t *info_cmds; // AWH - was term_cmd_t
  /*!
   * \brief callback for cleaning up states in plugin.
   * TEMU plugin must release all allocated resources in this function
   */
  void (*plugin_cleanup)(void);

#if 0 //LOK: Changed it from 1 to 0 - moved into the new tainting subdirectory // AWH TAINT_ENABLED
  /// \brief size of taint record for each tainted byte.
  /// TEMU sees taint record as untyped buffer, so it only cares about the
  /// size of taint record
  int taint_record_size;

#define PROP_MODE_MOVE  0
#define PROP_MODE_XFORM 1

  /// \brief This callback customizes its own policy for taint propagation
  ///
  /// TEMU asks plugin how to propagate tainted data. If the plugin does not
  /// want to customize the propagation policy, it can simply specify
  /// default_taint_propagate().
  ///
  /// @param nr_src number of source operands
  /// @param src_oprnds array of source operands
  /// @param dst_oprnd destination operand
  /// @param mode mode of propagation (either direct move or transformation)
  void (*taint_propagate) (int nr_src, taint_operand_t *src_oprnds,
                taint_operand_t *dst_oprnd, int mode);
#endif

#define GUEST_MESSAGE_LEN_MINUS_ONE 4095
#define GUEST_MESSAGE_LEN (GUEST_MESSAGE_LEN_MINUS_ONE+1)
  /// \brief This callback handles OS-level semantics information.
  ///
  /// It needs to parse the message and maintain process, module, and function
  /// information, using functionality in \ref semantics.
  void (*guest_message) (char *message);

  void (*send_keystroke) (int reg);
#if 0 //LOK: Removed the callback interfaces
  /// This callback is invoked at the beginning of each basic block
  int (*block_begin) (void);
  /// This callback is invoked at the end of each basic block
  void (*block_end) (void);
  /// This callback is invoked at the beginning of each instruction
  void (*insn_begin) (void);
  /// This callback is invoked at the end of each instruction
  void (*insn_end) (void);
#endif

#if 0 // AWH - block device interface changed
  void (*bdrv_open) (int index, void *opaque);
#else
  void (*bdrv_open) (BlockInterfaceType interType, int index, void *opaque);
#endif // AWH
  //LOK: Moved the following two functions into tainting.h
  //void (*taint_disk) (uint64_t addr, uint8_t * record, void *opaque);
  //void (*read_disk_taint)(uint64_t addr, uint8_t * record, void *opaque);
  /// This callback is invoked when a network packet is received by NIC
  void (*nic_recv) (uint8_t * buf, int size, int cur_pos, int start,
                    int stop);
  /// This callback is invoked when a network packet is sent out by NIC
  void (*nic_send) (uint32_t addr, int size, uint8_t * buf);

  int (*cjmp) (uint32_t t0);
#if 0 //LOK: Removed it too // AWH #ifdef DEFINE_EIP_TAINTED
  void (*eip_tainted) (uint8_t * record);
#endif
#ifdef DEFINE_MEMREG_EIP_CHANGE
  void (*memreg_eip_change)();
#endif
  void (*after_loadvm) (const char *param);
#ifdef CHEAT_SIDT
  int (*cheat_sidt) ();
#endif

  /// \brief CR3 of a specified process to be monitored.
  /// 0 means system-wide monitoring, including all processes and kernel.
  union
  {
    uint32_t monitored_cr3;
    uint32_t monitored_pgd; //alias
  };

#ifdef MEM_CHECK
  /// \brief This callback is invoked when the current instruction reads a memory region.
  ///
  /// @param virt_addr virtual address of memory region
  /// @param phys_addr physical address of memory region
  /// @param size size of memory region
  void (*mem_read)(uint32_t virt_addr, uint32_t phys_addr, int size);
  /// \brief This callback is invoked when the current instruction writes a memory region.
  ///
  /// @param virt_addr virtual address of memory region
  /// @param phys_addr physical address of memory region
  /// @param size size of memory region
  void (*mem_write)(uint32_t virt_addr, uint32_t phys_addr, int size);
#endif

#ifdef REG_CHECK
  /// \brief This callback is invoked when the current instruction reads a register.
  ///
  /// @param regidx register index, e.g., the index of R_BH is R_EBX*4 + 1
  /// @param size size of register in bytes
  void (*reg_read)(uint32_t regidx, int offset, int size);

  /// \brief This callback is invoked when the current instruction writes a register.
  ///
  /// @param regidx register index, e.g., the index of R_BH is R_EBX*4 + 1
  /// @param size size of register in bytes
  void (*reg_write)(uint32_t regidx, int offset, int size);
#endif

#ifdef HANDLE_INTERRUPT
  /// \brief This callback indicates an interrupt is happening
  ///
  /// @param intno interrupt number
  /// @param is_int is it software interrupt?
  /// @param next_eip EIP value when interrupt returns
  void (*do_interrupt)(int intno, int is_int, uint32_t next_eip);

  /// This callback indicates an interrupt is returned
  void (*after_iret_protected)();
#endif

#ifdef CALLSTRING_ANALYSIS
  void (*call_analysis)(uint32_t next_eip);
#endif

#ifdef PRE_MEM_WRITE
  void (*pre_mem_write)(uint32_t virt_addr, uint32_t phys_addr, int size);
#endif
#ifdef HANDLE_CPUID
  void (*cpuid_insn)();
#endif

#ifdef TLB_FILL_CALLBACK
  void (*tlb_fill_cb)(uint32_t virt_addr, uint32_t phys_addr);
#endif

#ifdef TEMU_LD_PHYS_CB
  void (*ld_phys_cb)(target_ulong addr, int size);
#endif

#ifdef TEMU_ST_PHYS_CB
  void (*st_phys_cb)(target_ulong addr, int size);
#endif

} plugin_interface_t;

extern plugin_interface_t *decaf_plugin;

void DECAF_do_load_plugin_internal(Monitor *mon, const char *plugin_path);
int do_load_plugin(Monitor *mon, const QDict *qdict, QObject **ret_data);
int do_unload_plugin(Monitor *mon, const QDict *qdict, QObject **ret_data);

/*************************************************************************
 * The Virtual Machine control
 *************************************************************************/

/// Pause the guest system
void DECAF_stop_vm(void);
// Unpause the guest system
void DECAF_start_vm(void);


/*************************************************************************
 * Functions for accessing the guest's CPU State
 * These are generic. Look in the target's DECAF_mains 
 * for target specific CPU accesses 
 *************************************************************************/

//Gets the current Program Counter value
gva_t DECAF_getPC(CPUState* env);

//Gets the current PGD value - this is CR3 in x86 and base0 in ARM
// Note that ARM has two PGD values though!
gpa_t DECAF_getPGD(CPUState* env);

gva_t DECAF_getESP(CPUState* env);

//returns the first parameter according to
// ABIs, i.e. env->regs[0] for ARM and env->regs[R_EAX] for x86
target_ulong DECAF_getFirstParam(CPUState* env);

gva_t DECAF_getReturnAddr(CPUState* env);

/*************************************************************************
 * Functions for accessing the guest's memory
 *************************************************************************/

/****** Functions used by DECAF plugins ****/
void DECAF_physical_memory_rw(CPUState* env, gpa_t addr, uint8_t *buf,
                            int len, int is_write);

#define DECAF_physical_memory_read(_env, addr, buf, len) \
        DECAF_physical_memory_rw(_env, addr, buf, len, 0)

#define DECAF_physical_memory_write(_env, addr, buf, len) \
        DECAF_physical_memory_rw(_env, addr, buf, len, 1)

/// Convert virtual address into physical address
gpa_t DECAF_get_phys_addr(CPUState* env, gva_t addr);

/// Convert virtual address into physical address for given pgd - a phys addr
//The implementation is target-specific
gpa_t DECAF_get_phys_addr_with_pgd(CPUState* env, gpa_t pgd, gva_t addr);

//wrapper -- pgd is the generic term while cr3 is the register in x86
#define DECAF_get_phys_addr_with_cr3(_env, _pgd, _addr) \
        DECAF_get_phys_addr_with_pgd(_env, _pgd, _addr)

DECAF_errno_t DECAF_memory_rw(CPUState* env, gva_t addr, void *buf, int len, int is_write);

//The implementation is target-specific
DECAF_errno_t DECAF_memory_rw_with_pgd(CPUState* env, target_ulong pgd, gva_t addr, void *buf,
                            int len, int is_write);

#define DECAF_memory_rw_with_cr3(_env, _pgd, _addr, _buf, _len, _is_write) \
        DECAF_memory_rw_with_pgd(_env, _pgd, _addr, _buf, _len, _is_write)

/// \brief Read from a memory region by its virtual address.
///
/// @param vaddr virtual memory address
/// @param buf output buffer of the value to be read
/// @param len length of memory region (in bytes)
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted
/// into physical address. It could be either invalid address or swapped out.
#define DECAF_read_mem(_env, _vaddr, _buf, _len) \
        DECAF_memory_rw(_env, _vaddr, _buf, _len, 0)

///
/// @param vaddr virtual memory address
/// @param buf input buffer of the value to be written
/// @param len length of memory region (in bytes)
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted
/// into physical address. It could be either invalid address or swapped out.
#define DECAF_write_mem(_env, _vaddr, _buf, _len) \
        DECAF_memory_rw(_env, _vaddr, _buf, _len, 1)

/** 
 * Read memory starting from guest virtual address vaddr with page tables in pgd
 * NOTE1: This accesses the memory directly and will not affect the TLB cache
 * NOTE2: This implementation is NOT target specific because it uses the get phys page pgd 
 *   function above.
 * @param env The context
 * @param pgd The new pgd to use
 * @param vaddr The guest virtual address
 * @param buf Where to write the bytes to
 * @param len The number of bytes to read
 * @return 0 if successful
**/
#define DECAF_read_mem_with_pgd(_env, _pgd, _vaddr, _buf, _len) \
        DECAF_memory_rw_with_pgd(_env, _pgd, _vaddr, _buf, _len, 0)

#define DECAF_read_mem_with_cr3(_env, _pgd, _vaddr, _len, _buf) \
        DECAF_read_mem_with_pgd(_env, _pgd, _vaddr, _len, _buf)

/**
 * Write memory starting from guest virtual address vaddr using pgd
**/
#define DECAF_write_mem_with_pgd(_env, _pgd, _vaddr, _buf, _len) \
        DECAF_memory_rw_with_pgd(_env, _pgd, _vaddr, _buf, _len, 1)

#define DECAF_write_mem_with_cr3(_env, _pgd, _vaddr, _len, _buf) \
        DECAF_write_mem_with_pgd(_env, _pgd, _vaddr, _len, _buf)


/**
 * Read memory starting from guest virtual address vaddr into buf until either
 *   The 0 byte is read in
 *   Len bytes are read in or
 *   A read error occurred
 * Good for reading CStrings
 * @param env The context
 * @param vaddr The guest virtual address
 * @param len The maximum number of bytes to read
 * @param buf The buffer to put the bytes read in to
 * @return Number of bytes read
 * @return Negative if unsuccessful
 */
int DECAF_read_mem_until(CPUState* env, gva_t vaddr, void* buf, size_t len);

extern void * DECAF_KbdState;

/// \brief Set monitor context.
///
/// This is a boolean flag that indicates if the current execution needs to be monitored
/// and analyzed by the plugin. The default value is 1, which means that the plugin wants
/// to monitor all execution (including the OS kernel and all running applications).
/// Very often, the plugin is only interested in a single user-level process.
/// In this case, the plugin is responsible to set this flag to 1 when the execution is within
/// the specified process and to 0 when it is not.
extern int should_monitor;

//extern int do_enable_emulation(Monitor *mon, const QDict *qdict, QObject **ret_data);
//extern int do_disable_emulation(Monitor *mon, const QDict *qdict, QObject **ret_data);


int DECAF_bdrv_pread(void *bs, int64_t offset, void *buf, int count); //for SleuthKit

extern int DECAF_emulation_started; //will be removed

//In DECAF - we do not use the same-per vcpu flushing behavior as in QEMU. For example
// DECAF_flushTranslationCache is a wrapper for tb_flush that iterates through all of
// the virtual CPUs and calls tb_flush on that particular environment. The main reasoning
// behind this decision is that the user wants to know when an event occurs for any
// vcpu and not only for specific ones. This idea can change in the future of course.
// We have yet to decide how to handle multi-core analysis, at the program abstraction
// level or at the thread execution level or at the virtual cpu core level?
//No matter what the decision, flushing can occur using the CPUState as in QEMU
// or using DECAF's wrappers.

/**
 * Flush - or invalidate - the translation block for address addr in the env context.
 * @param env The cpu context
 * @param addr The block's address
 */
void DECAF_flushTranslationBlock_env(CPUState* env, gva_t addr);

/**
 * Flush - or invalidate - all translation blocks for the page in addr.
 * Note that in most cases TARGET_PAGE_SIZE is 4k in size, which is expected.
 *  However, in some cases it might only be 1k (in ARM). We use TARGET_PAGE_SIZE
 *  as the mask in this function
 *
 * @param env The cpu context
 * @param addr The page address
 */
void DECAF_flushTranslationPage_env(CPUState* env, gva_t addr);

//These are DECAF wrappers that does flushing for all VCPUs

//Iterates through all virtual cpus and flushes the blocks
static inline void DECAF_flushTranslationBlock(uint32_t addr)
{
  CPUState* env;
  for(env = first_cpu; env != NULL; env = env->next_cpu)
  {
    DECAF_flushTranslationBlock_env(env, addr);
  }
}

//Iterates through all virtual cpus and flushes the pages
static inline void DECAF_flushTranslationPage(uint32_t addr)
{
  CPUState* env;
  for(env = first_cpu; env != NULL; env = env->next_cpu)
  {
    DECAF_flushTranslationPage_env(env, addr);
  }
}

//Iterates through all virtual cpus and flushes the pages
static inline void DECAF_flushTranslationCache(void)
{
  CPUState* env;
  for(env = first_cpu; env != NULL; env = env->next_cpu)
  {
    tb_flush(env);
  }
}

/* Static in monitor.c for QEMU, but we use it for plugins: */
///send a keystroke into the guest system
extern void do_send_key(const char *string);

#ifdef __cplusplus
}
#endif

#endif /* DECAF_MAIN_H_ */
