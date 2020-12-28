/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
#define __STDC_FORMAT_MACROS

// The return of some linux system calls is not always handled
// correctly. This needs further investigation.
// Uncomment next lines to enable debug prints for tracking of system
// call context. Only for x86
//#define SYSCALL_RETURN_DEBUG
//#define PANDA_LOG_LEVEL PANDA_LOG_DEBUG

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <functional>
#include <string>
#include <algorithm>
#include <memory>
#include <vector>
#include <iostream>
#include <sstream>

#include "syscalls2.h"
#include "syscalls2_info.h"

bool translate_callback(CPUState *cpu, target_ulong pc);
int exec_callback(CPUState *cpu, target_ulong pc);

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
void registerExecPreCallback(void (*callback)(CPUState*, target_ulong));

// API calls
#include "syscalls2_int_fns.h"

// PPP code
#include "syscalls_ext_typedefs.h"
#include "generated/syscall_ppp_boilerplate_enter.cpp"
#include "generated/syscall_ppp_boilerplate_return.cpp"
#include "generated/syscall_ppp_register_enter.cpp"
#include "generated/syscall_ppp_register_return.cpp"
}

// Forward declarations
int32_t get_s32_generic(CPUState *cpu, uint32_t argnum);
int64_t get_s64_generic(CPUState *cpu, uint32_t argnum);
int32_t get_return_s32_generic(CPUState *cpu, uint32_t argnum);
int64_t get_return_s64_generic(CPUState *cpu, uint32_t argnum);
target_long get_return_val_x86(CPUState *cpu);
target_long get_return_val_arm(CPUState *cpu);
target_long get_return_val_mips(CPUState *cpu);
uint32_t get_return_32_windows_x86(CPUState *cpu, uint32_t argnum);
uint64_t get_return_64_windows_x86(CPUState *cpu, uint32_t argnum);
uint64_t get_64_linux_x86(CPUState *cpu, uint32_t argnum);
uint64_t get_64_linux_x64(CPUState *cpu, uint32_t argnum);
uint64_t get_64_linux_arm(CPUState *cpu, uint32_t argnum);
uint64_t get_64_linux_mips(CPUState *cpu, uint32_t argnum);
uint64_t get_64_windows_x86(CPUState *cpu, uint32_t argnum);
uint32_t get_32_linux_x86(CPUState *cpu, uint32_t argnum);
uint32_t get_32_linux_x64(CPUState *cpu, uint32_t argnum);
uint32_t get_32_linux_arm(CPUState *cpu, uint32_t argnum);
uint32_t get_32_linux_mips(CPUState *cpu, uint32_t argnum);
uint32_t get_32_windows_x86(CPUState *cpu, uint32_t argnum);
target_ulong calc_retaddr_windows_x86(CPUState *cpu, target_ulong pc);
target_ulong calc_retaddr_linux_x86(CPUState *cpu, target_ulong pc);
target_ulong calc_retaddr_linux_x64(CPUState *cpu, target_ulong pc);
target_ulong calc_retaddr_linux_arm(CPUState *cpu, target_ulong pc);
target_ulong calc_retaddr_linux_mips(CPUState *cpu, target_ulong pc); // TODO

enum ProfileType {
    PROFILE_LINUX_X86,
    PROFILE_LINUX_ARM,
    PROFILE_LINUX_AARCH64,
    PROFILE_LINUX_MIPS,
    PROFILE_WINDOWS_2000_X86,
    PROFILE_WINDOWS_XPSP2_X86,
    PROFILE_WINDOWS_XPSP3_X86,
    PROFILE_WINDOWS_7_X86,
	PROFILE_LINUX_X64,
	PROFILE_FREEBSD_X64,
    PROFILE_LAST
};

struct Profile {
    void         (*enter_switch)(CPUState *, target_ulong);
    void         (*return_switch)(CPUState *, target_ulong, const syscall_ctx_t *);
    target_long  (*get_return_val )(CPUState *);
    target_ulong (*calc_retaddr )(CPUState *, target_ulong);
    uint32_t     (*get_32 )(CPUState *, uint32_t);
    int32_t      (*get_s32)(CPUState *, uint32_t);
    uint64_t     (*get_64)(CPUState *, uint32_t);
    int64_t      (*get_s64)(CPUState *, uint32_t);
    uint32_t     (*get_return_32 )(CPUState *, uint32_t);
    int32_t      (*get_return_s32)(CPUState *, uint32_t);
    uint64_t     (*get_return_64)(CPUState *, uint32_t);
    int64_t      (*get_return_s64)(CPUState *, uint32_t);
    int          windows_return_addr_register;
    int          windows_arg_offset;
    int          syscall_interrupt_number;
};

Profile profiles[PROFILE_LAST] = {
    { /* PROFILE_LINUX_X86 */
        .enter_switch = syscall_enter_switch_linux_x86,
        .return_switch = syscall_return_switch_linux_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_linux_x86,
        .get_32 = get_32_linux_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_x86,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_32_linux_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_x86,
        .get_return_s64 = get_return_s64_generic,
        .windows_return_addr_register = -1,
        .windows_arg_offset = -1,
        .syscall_interrupt_number = 0x80,
    },
    { /* PROFILE_LINUX_ARM */
        .enter_switch = syscall_enter_switch_linux_arm,
        .return_switch = syscall_return_switch_linux_arm,
        .get_return_val = get_return_val_arm,
        .calc_retaddr = calc_retaddr_linux_arm,
        .get_32 = get_32_linux_arm,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_arm,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_32_linux_arm,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_arm,
        .get_return_s64 = get_return_s64_generic,
        .windows_return_addr_register = -1,
        .windows_arg_offset = -1,
        .syscall_interrupt_number = 0x80,
    },
    {   /* PROFILE_LINUX_AARCH64 */
        .enter_switch = syscall_enter_switch_linux_arm64,
        .return_switch = syscall_return_switch_linux_arm64,
        .get_return_val = get_return_val_arm,
        .calc_retaddr = calc_retaddr_linux_arm,
        .get_32 = get_32_linux_arm,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_arm,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_32_linux_arm,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_arm,
        .get_return_s64 = get_return_s64_generic,
        .windows_return_addr_register = -1,
        .windows_arg_offset = -1,
        .syscall_interrupt_number = 0x80,
    },
    {   /* Linux MIPS */
        .enter_switch = syscall_enter_switch_linux_mips,
        .return_switch = syscall_return_switch_linux_mips,
        .get_return_val = get_return_val_mips,
        .calc_retaddr = calc_retaddr_linux_mips,
        .get_32 = get_32_linux_mips,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_mips,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_32_linux_mips,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_mips,
        .get_return_s64 = get_return_s64_generic,
        .windows_return_addr_register = -1,
        .windows_arg_offset = -1,
        .syscall_interrupt_number = 0x80,
    },
    {
        .enter_switch = syscall_enter_switch_windows_2000_x86,
        .return_switch = syscall_return_switch_windows_2000_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_windows_x86,
        .get_32 = get_32_windows_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_windows_x86,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_return_32_windows_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_return_64_windows_x86,
        .get_return_s64 = get_return_s64_generic,
#if defined(TARGET_I386)
        .windows_return_addr_register = R_ESP,
#else
        .windows_return_addr_register = -1,
#endif
        .windows_arg_offset = 0,
        .syscall_interrupt_number = 0x2E,
    },
    {
        .enter_switch = syscall_enter_switch_windows_xpsp2_x86,
        .return_switch = syscall_return_switch_windows_xpsp2_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_windows_x86,
        .get_32 = get_32_windows_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_windows_x86,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_return_32_windows_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_return_64_windows_x86,
        .get_return_s64 = get_return_s64_generic,
#if defined(TARGET_I386)
        .windows_return_addr_register = R_EDX,
#else
        .windows_return_addr_register = -1,
#endif
        .windows_arg_offset = 8,
        .syscall_interrupt_number = 0x80,
    },
    {
        .enter_switch = syscall_enter_switch_windows_xpsp3_x86,
        .return_switch = syscall_return_switch_windows_xpsp3_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_windows_x86,
        .get_32 = get_32_windows_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_windows_x86,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_return_32_windows_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_return_64_windows_x86,
        .get_return_s64 = get_return_s64_generic,
#if defined(TARGET_I386)
        .windows_return_addr_register = R_EDX,
#else
        .windows_return_addr_register = -1,
#endif
        .windows_arg_offset = 8,
        .syscall_interrupt_number = 0x80,
    },
    {
        .enter_switch = syscall_enter_switch_windows_7_x86,
        .return_switch = syscall_return_switch_windows_7_x86,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_windows_x86,
        .get_32 = get_32_windows_x86,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_windows_x86,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_return_32_windows_x86,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_return_64_windows_x86,
        .get_return_s64 = get_return_s64_generic,
#if defined(TARGET_I386)
        .windows_return_addr_register = R_EDX,
#else
        .windows_return_addr_register = -1,
#endif
        .windows_arg_offset = 8,
        .syscall_interrupt_number = 0x80,
    },
    {
        .enter_switch = syscall_enter_switch_linux_x64,
        .return_switch = syscall_return_switch_linux_x64,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_linux_x64,
        .get_32 = get_32_linux_x64,
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_x64,
        .get_s64 = get_s64_generic,
        .get_return_32 = get_32_linux_x64,
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_x64,
        .get_return_s64 = get_return_s64_generic,
        .windows_return_addr_register = -1,
        .windows_arg_offset = -1,
        .syscall_interrupt_number = 0x80,
    },
    {
        .enter_switch = syscall_enter_switch_freebsd_x64,
        .return_switch = syscall_return_switch_freebsd_x64,
        .get_return_val = get_return_val_x86,
        .calc_retaddr = calc_retaddr_linux_x64, // Not auto-gen, using the Linux impl
        .get_32 = get_32_linux_x64,             // Not auto-gen, using the Linux impl
        .get_s32 = get_s32_generic,
        .get_64 = get_64_linux_x64,             // Not auto-gen, using the Linux impl
        .get_s64 = get_s64_generic,
        .get_return_32 = get_32_linux_x64,      // Not auto-gen, using the Linux impl
        .get_return_s32 = get_return_s32_generic,
        .get_return_64 = get_64_linux_x64,      // Not auto-gen, using the Linux impl
        .get_return_s64 = get_return_s64_generic,
        .windows_return_addr_register = -1,
        .windows_arg_offset = -1,
        .syscall_interrupt_number = 0x80,
    }
};

static Profile *syscalls_profile;

// TODO (tnballo): MIPS has weird ABI variations and we eventually need a way to support them via external param/config,
// this includes ordinal number variations (4XXX, 5XXX, 6XXX). See: https://www.linux-mips.org/wiki/P32_Linux_ABI
// For now, let's just be biased toward O32 here - seems to be most of our dataset?
#define MIPS_O32_ABI

// Reinterpret the ulong as a long. Arch and host specific.
target_long get_return_val_x86(CPUState *cpu){
#if defined(TARGET_I386)
    // this should work for X86_64 as well, as PANDA uses R_EAX to access RAX
	// and target_ulong changes size based on the target
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    return static_cast<target_long>(env->regs[R_EAX]);
#endif
    return 0;
}

target_long get_return_val_arm(CPUState *cpu){
#if defined(TARGET_ARM)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
#if !defined(TARGET_AARCH64)
    // arm: reg[0]
    return static_cast<target_long>(env->regs[0]);
#else
    // aarch64: xregs[0]
    return static_cast<target_long>(env->xregs[0]);
#endif

#endif
    return 0;
}

target_long get_return_val_mips(CPUState *cpu){
#if defined(TARGET_MIPS)
    // Return values are in $v0, $v1 (regs 2 and 3 respectively)
    // $v0 only for almost all for Linux syscalls
    // $v1 returns 2nd file descriptor only for pipe(2) - we'll just ignore this edge case
    // See: https://www.linux-mips.org/wiki/Syscall
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    return static_cast<target_long>(env->active_tc.gpr[2]);
#endif
    return 0;
}

target_ulong mask_retaddr_to_pc(target_ulong retaddr){
    target_ulong mask = std::numeric_limits<target_ulong>::max() -1;
    return retaddr & mask;
}

// Return address calculations
target_ulong calc_retaddr_windows_x86(CPUState* cpu, target_ulong pc) {
#if defined(TARGET_I386)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    target_ulong retaddr = 0;
    assert(syscalls_profile->windows_return_addr_register >= 0);
    panda_virtual_memory_rw(cpu, env->regs[syscalls_profile->windows_return_addr_register], (uint8_t *) &retaddr, 4, false);
    return retaddr;
#else
    // shouldn't happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_x86(CPUState* cpu, target_ulong pc) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    unsigned char buf[2] = {};
    panda_virtual_memory_rw(cpu, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05) or  sysenter (0F 34)
    if ((buf[0]== 0x0F && buf[1] == 0x05) || (buf[0]== 0x0F && buf[1] == 0x34)) {
        // For Linux system calls using sysenter, we need to look on the stack.
        // https://reverseengineering.stackexchange.com/questions/2869/how-to-use-sysenter-under-linux
        target_ulong ret = 0x0;
        target_ulong ret_ptr =
            ((CPUX86State *)cpu->env_ptr)->regs[R_ESP] + 0x0C;
        panda_virtual_memory_read(cpu, ret_ptr, (uint8_t *)&ret, sizeof(ret));
        assert(ret != 0x0);
        return ret;
    }
    // Check if the instruction is int 0x80 (CD 80)
    else if (buf[0]== 0xCD && buf[1] == 0x80) {
        return pc+2;
    }
    // shouldn't happen
    else {
        assert(1==0);
    }
#else
    // shouldn't happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_x64(CPUState* cpu, target_ulong pc) {
#if defined(TARGET_X86_64)
    unsigned char buf[2] = {};
    panda_virtual_memory_rw(cpu, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05)
    if ((0x0F == buf[0]) && (0x05 == buf[1])) {
        // syscall expects the return address to be in RCX, but sometimes RCX is
    	// still 0 at this point; so calculate the return address from the pc
        target_ulong ret = pc + 2;
        assert(ret != 0x0);
        return ret;
    }
    // shouldn't happen
    else {
        assert(1==0);
    }
#else
    // shouldn't happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_arm(CPUState* cpu, target_ulong pc) {
#if defined(TARGET_ARM)
    // Normal syscalls: return addr is stored in LR
    // Except that we haven't run the SWI instruction yet! LR is where libc will return to!
    //return mask_retaddr_to_pc(env->regs[14]);

    // Fork, exec
#if !defined(TARGET_AARCH64)
    uint8_t offset = 0;
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
#else
    uint8_t offset = 8;
#endif
    return mask_retaddr_to_pc(pc + offset);
#else
    // shouldnt happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_mips(CPUState* cpu, target_ulong pc) {
#if defined(TARGET_MIPS)
    // Normal calls: return address is in $ra which is reg 31
    // System calls: address of instruction that caused the interrupt is in $EPC, a special register for co-processor 0
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    return env->CP0_EPC;
#else
    // shouldnt happen
    assert (1==0);
#endif
}

// Argument getting (at syscall entry)
uint32_t get_linux_x86_argnum(CPUState *cpu, uint32_t argnum) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    switch (argnum) {
    case 0:
        return env->regs[R_EBX];
        break;
    case 1:
        return env->regs[R_ECX];
        break;
    case 2:
        return env->regs[R_EDX];
        break;
    case 3:
        return env->regs[R_ESI];
        break;
    case 4:
        return env->regs[R_EDI];
        break;
    case 5:
        return env->regs[R_EBP];
        break;
    }
    assert (1==0);
#endif
    return 0;
}

// Argument getting (at syscall entry)
uint64_t get_linux_x64_argnum(CPUState *cpu, uint32_t argnum) {
#if defined(TARGET_X86_64)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // PANDA uses x86 register names to get at the x64 registers
    switch (argnum) {
    case 0:
    	// RDI
        return env->regs[R_EDI];
        break;
    case 1:
    	// RSI
        return env->regs[R_ESI];
        break;
    case 2:
    	// RDX
        return env->regs[R_EDX];
        break;
    case 3:
    	// R10
        return env->regs[10];
        break;
    case 4:
    	// R8
        return env->regs[8];
        break;
    case 5:
    	// R9
        return env->regs[9];
        break;
    }
    assert (1==0);
#endif
    return 0;
}

static uint32_t get_win_syscall_arg(CPUState* cpu, int nr) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at env->regs[R_EDX]+8
    // At INT 0x2E on Windows 2000, args start at env->regs[R_EDX]
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    uint32_t arg = 0;
    assert(syscalls_profile->windows_arg_offset >= 0);
    panda_virtual_memory_rw(cpu, env->regs[R_EDX] + syscalls_profile->windows_arg_offset + (4*nr),
                            (uint8_t *) &arg, 4, false);
    return arg;
#endif
    return 0;
}

uint32_t get_32_linux_x86 (CPUState *cpu, uint32_t argnum) {
    assert (argnum < 6);
    return (uint32_t) get_linux_x86_argnum(cpu, argnum);
}
uint32_t get_32_linux_x64 (CPUState *cpu, uint32_t argnum) {
    assert (argnum < 6);
    return (uint32_t) (get_linux_x64_argnum(cpu, argnum) & 0xFFFFFFFF);
}
uint32_t get_32_linux_arm (CPUState *cpu, uint32_t argnum) {
#ifdef TARGET_ARM
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

#if !defined(TARGET_AARCH64)
    // arm32 regs in r0-r6
    assert (argnum < 7);
    return (uint32_t) env->regs[argnum];
#else
    // aarch64 regs in x0-x5
    assert (argnum < 6);
    return (uint32_t) env->xregs[argnum];
#endif

#else
    return 0;
#endif
}

uint32_t get_32_linux_mips (CPUState *cpu, uint32_t argnum) {
#ifdef TARGET_MIPS
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // https://www.linux-mips.org/wiki/P32_Linux_ABI
    #ifdef MIPS_O32_ABI
        assert (argnum < 8);

        // Args 1-4 in $a0-$a3 which are regs 4-7 in gpr
        if (argnum < 4) {

            return (uint32_t) env->active_tc.gpr[argnum+4];

        // Args 5-8 on the stack
        // 4 <= argnum < 8
        } else {

            uint32_t buf;
            target_ulong arg_stack_addr = env->active_tc.gpr[29] + 16 + ((argnum - 4) * 4);
            int res = panda_virtual_memory_read(cpu, arg_stack_addr, (uint8_t*)&buf, 4);

            if (res < 0) {
                // TODO: we need an error propagation methodology in this codebase, func sig assumes success
            }

            return buf;
        }
    #else
        // Args 1-6 in $a0-$a5 which are regs 4-9 in gpr
        assert (argnum < 6);
        return (uint32_t) env->active_tc.gpr[argnum+4];
    #endif

#else
    return 0;
#endif
}

uint32_t get_32_windows_x86 (CPUState *cpu, uint32_t argnum) {
    return (uint32_t) get_win_syscall_arg(cpu, argnum);
}

uint64_t get_64_linux_x86(CPUState *cpu, uint32_t argnum) {
    assert (argnum < 6);
    return (((uint64_t) get_linux_x86_argnum(cpu, argnum)) << 32) | (get_linux_x86_argnum(cpu, argnum));
}

uint64_t get_64_linux_x64(CPUState *cpu, uint32_t argnum) {
    assert (argnum < 6);
    return (uint64_t) get_linux_x64_argnum(cpu, argnum);
}

uint64_t get_64_linux_arm(CPUState *cpu, uint32_t argnum) {
#ifdef TARGET_ARM
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
#if !defined(TARGET_AARCH64)
    // arm32 regs in r0-r6
    assert (argnum < 7);
    return (((uint64_t) env->regs[argnum]) << 32) | (env->regs[argnum+1]);
#else
    // aarch64 fits 64 bit registers in regs in x0-x5
    assert (argnum < 6);
    return (uint64_t) env->xregs[argnum];
#endif
#else
    return 0;
#endif
}

uint64_t get_64_linux_mips(CPUState *cpu, uint32_t argnum) {
#ifdef TARGET_MIPS
    // Args 1-6 in $a0-$a5 which are regs 4-9 in gpr
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    assert (argnum < 6);
    return env->active_tc.gpr[argnum+4];
#else
    return 0;
#endif
}

uint64_t get_64_windows_x86(CPUState *cpu, uint32_t argnum) {
    assert (false && "64-bit arguments not supported on Windows 7 x86");
    return 0;
}

// Argument getting (at syscall return)
static uint32_t get_win_syscall_return_arg(CPUState* cpu, int nr) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at env->regs[R_EDX]+8
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    uint32_t arg = 0;
    panda_virtual_memory_rw(cpu, env->regs[R_ESP] + 4 + (4*nr),
                            (uint8_t *) &arg, 4, false);
    return arg;
#else
    return 0;
#endif
}

uint32_t get_return_32_windows_x86 (CPUState *cpu, uint32_t argnum) {
    return get_win_syscall_return_arg(cpu, argnum);
}

uint64_t get_return_64_windows_x86(CPUState *cpu, uint32_t argnum) {
    assert (false && "64-bit arguments not supported on Windows 7 x86");
}

// Wrappers
target_long get_return_val (CPUState *cpu) {
    return syscalls_profile->get_return_val(cpu);
}
target_ulong calc_retaddr (CPUState *cpu, target_ulong pc) {
    return syscalls_profile->calc_retaddr(cpu, pc);
}
uint32_t get_32(CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_32(cpu, argnum);
}
int32_t get_s32(CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_s32(cpu, argnum);
}
uint64_t get_64(CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_64(cpu, argnum);
}
int64_t get_s64(CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_s64(cpu, argnum);
}
uint32_t get_return_32 (CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_return_32(cpu, argnum);
}
int32_t get_return_s32(CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_return_s32(cpu, argnum);
}
uint64_t get_return_64(CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_return_64(cpu, argnum);
}
int64_t get_return_s64(CPUState *cpu, uint32_t argnum) {
    return syscalls_profile->get_return_s64(cpu, argnum);
}

int32_t get_s32_generic(CPUState *cpu, uint32_t argnum) {
    return (int32_t) get_32(cpu, argnum);
}

int64_t get_s64_generic(CPUState *cpu, uint32_t argnum) {
    return (int64_t) get_64(cpu, argnum);
}

int32_t get_return_s32_generic(CPUState *cpu, uint32_t argnum) {
    return (int32_t) get_return_32(cpu, argnum);
}

int64_t get_return_s64_generic(CPUState *cpu, uint32_t argnum) {
    return (int64_t) get_return_64(cpu, argnum);
}

static std::vector<void (*)(CPUState*, target_ulong)> preExecCallbacks;

void registerExecPreCallback(void (*callback)(CPUState*, target_ulong)){
    preExecCallbacks.push_back(callback);
}

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

/**
 * @brief Map holding the context of ongoing system calls. An unfinished
 * system call can be uniquely identified by its return address and the
 * asid of the process that invoked it. This pair is used as the key to
 * the map.
 */
context_map_t running_syscalls;

#if defined(SYSCALL_RETURN_DEBUG)
/**
 * @brief Returns a string representation of a context_map_t container.
 */
static inline std::string context_map_t_dump(context_map_t &cm) {
    const syscall_info_t *si = syscall_info;
    const syscall_meta_t *sm = syscall_meta;
    std::stringstream ss;
    ss << "{";
    for (auto ctxi = cm.begin(); ctxi != cm.end(); ++ctxi) {
	    syscall_ctx_t *ctx = &ctxi->second;
	    ss << " ";
	    if (si == NULL || ctx->no > sm->max_generic) {
	        ss << ctx->no;
	    } else {
	        ss << si[ctx->no].name;
	    }
	    ss << ":" << std::hex << ctx->asid;
	    ss << ",";
    }
    ss.seekp(-1, ss.cur);
    ss << " }";
    return ss.str();
}
#endif

#if defined(TARGET_PPC)
#else
/**
 * @brief Checks if the translation block that is about to be executed
 * matches the return address of an executing system call.
 */
static void tb_check_syscall_return(CPUState *cpu, TranslationBlock *tb) {
    auto k = std::make_pair(tb->pc, panda_current_asid(cpu));
    auto ctxi = running_syscalls.find(k);
    int UNUSED(no) = -1;
    if (ctxi != running_syscalls.end()) {
        syscall_ctx_t *ctx = &ctxi->second;
        no = ctx->no;
        syscalls_profile->return_switch(cpu, tb->pc, ctx);
        running_syscalls.erase(ctxi);
    }
#if defined(SYSCALL_RETURN_DEBUG)
    if (no >= 0) {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
        // If not guarded we get unused variable warning
        const syscall_info_t *si = syscall_info;
        const syscall_meta_t *sm = syscall_meta;
        std::string remaining = context_map_t_dump(running_syscalls);
        LOG_DEBUG("returned: %s:" TARGET_PTR_FMT, (no > sm->max_generic ? "N/A" : si[no].name), panda_current_asid(cpu));
        LOG_DEBUG("remaining %zu: %s\n", running_syscalls.size(), remaining.c_str());
#endif
    }
#endif
    return;
}
#endif

#ifdef DEBUG
static std::map<target_ulong,target_ulong> syscallCounter;
static uint32_t impossibleToReadPCs = 0;
#endif

// Check if the instruction is sysenter (0F 34),
// syscall (0F 05) or int 0x80 (CD 80)
int isCurrentInstructionASyscall(CPUState *cpu, target_ulong pc) {
#if defined(TARGET_I386)
    unsigned char buf[2] = {};

    int res = panda_virtual_memory_rw(cpu, pc, buf, 2, 0);
    if(res <0){
        return -1;
    }

    // Check if the instruction is syscall (0F 05)
    if (buf[0]== 0x0F && buf[1] == 0x05) {
        return true;
    }
    // Check if the instruction is int 0x80 (CD 80)
    else if (buf[0]== 0xCD && buf[1] == syscalls_profile->syscall_interrupt_number) {
#if defined(TARGET_X86_64)
        LOG_WARNING("32-bit system call (int 0x80) found in 64-bit replay - ignoring\n");
        return false;
#else
        return true;
#endif
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0]== 0x0F && buf[1] == 0x34) {
#if defined(TARGET_X86_64)
        LOG_WARNING("32-bit sysenter found in 64-bit replay - ignoring\n");
        return false;
#else
        return true;
#endif
    }
    else {
        return false;
    }
#elif defined(TARGET_ARM)
    unsigned char buf[4] = {};

#if defined(TARGET_AARCH64)
    // AARCH64 - No thumb mode, syscall is 01 00 00 d4
    // Check for ARM mode syscall
    panda_virtual_memory_rw(cpu, pc, buf, 4, 0);

    if ( (buf[0] == 0x01)  && (buf[1] == 0) && (buf[2] == 0) && (buf[3] == 0xd4) ) {
        return true;
    }

#else
    // ARM32
    // Check for ARM mode syscall
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if(env->thumb == 0) {
        panda_virtual_memory_rw(cpu, pc, buf, 4, 0);
        // EABI
        if ( ((buf[3] & 0x0F) ==  0x0F)  && (buf[2] == 0) && (buf[1] == 0) && (buf[0] == 0) ) {
            return true;
        }
#if defined(CAPTURE_ARM_OABI)
        else if (((buf[3] & 0x0F) == 0x0F)  && (buf[2] == 0x90)) {  // old ABI
            return true;
        }
#endif
    }
    else {
        panda_virtual_memory_rw(cpu, pc, buf, 2, 0);
        // check for Thumb mode syscall
        if (buf[1] == 0xDF && buf[0] == 0){
            return true;
        }
    }
#endif
    // Arm32/aarch64 - not a match
    return false;
#elif defined(TARGET_MIPS)

    unsigned char buf[4] = {};

    int res = panda_virtual_memory_read(cpu, pc, buf, 4);
    if(res < 0){
        return -1; // TODO: does caller even handle error case? Not every arch does it...
    }

    // ifdef guard prevents us from misinterpreting "syscall" as "jal 0x0000" or "ehb"
    #if defined(TARGET_WORDS_BIGENDIAN)
        // 32-bit MIPS "syscall" instruction - big endian
        return ((buf[0] == 0x00) && (buf[1] == 0x00) && (buf[2] == 0x00) && (buf[3] == 0x0c));
    #else
        // 32-bit MIPS "syscall" instruction - little endian
        return ((buf[3] == 0x00) && (buf[2] == 0x00) && (buf[1] == 0x00) && (buf[0] == 0x0c));
    #endif

    return false;

#elif defined(TARGET_PPC)
    return false;
#else
    return false; // helpful as a catchall for other architectures
#endif
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *cpu, target_ulong pc) {
    int res = isCurrentInstructionASyscall(cpu,pc);
#if defined(SYSCALL_RETURN_DEBUG) && defined(TARGET_I386)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    int no = env->regs[R_EAX];
    const syscall_info_t *si = syscall_info;
    const syscall_meta_t *sm = syscall_meta;
#endif
#ifdef DEBUG
    if(res < 0){
        impossibleToReadPCs++;
    }
#endif
    if(res == 1){
        // run any code we need to update our state
        for(const auto callback : preExecCallbacks){
            callback(cpu, pc);
        }
        // Call into autogenerated code for the current syscall!
        syscalls_profile->enter_switch(cpu, pc);

#if defined(SYSCALL_RETURN_DEBUG) && defined(TARGET_I386)
    if (no >= 0 && !si[no].noreturn) {
        std::string remaining = context_map_t_dump(running_syscalls);
        const char *c = (rr_get_guest_instr_count() > 7726588867 ? "X" : "");
        LOG_DEBUG("started%s: %s:" TARGET_PTR_FMT, c, (no > sm->max_generic ? "N/A" : si[no].name), panda_current_asid(cpu));
        LOG_DEBUG("remaining %zu: %s\n", running_syscalls.size(), remaining.c_str());
    }
#endif
#ifdef DEBUG
        syscallCounter[panda_current_asid(cpu)]++;
#endif
    }
    return 0;
}

bool translate_callback(CPUState* cpu, target_ulong pc){
    return isCurrentInstructionASyscall(cpu, pc) == 1;
}


/* ### API calls ######################################################## */
/*!
 * @brief Returns a pointer to the meta-information for the specified syscall.
 */
target_long get_syscall_retval(CPUState *cpu) {
    return syscalls_profile->get_return_val(cpu);
}

/*!
 * @brief Returns a pointer to the meta-information for the specified syscall.
 */
const syscall_info_t *get_syscall_info(uint32_t callno) {
    if (syscall_info != NULL) {
        return &syscall_info[callno];
    } else {
        return NULL;
    }
}

/*!
 * @brief Returns a pointer to the array containing the meta-information
 * for all syscalls.
 */
const syscall_meta_t *get_syscall_meta(void) { return syscall_meta; }


/* ### Plugin bootstrapping ############################################# */
bool init_plugin(void *self) {
// Don't bother if we're not on a supported target
#if defined(TARGET_I386) || defined(TARGET_ARM) || defined(TARGET_MIPS)
    if(panda_os_familyno == OS_UNKNOWN){
        std::cerr << PANDA_MSG "ERROR No OS profile specified. You can choose one with the -os switch, eg: '-os linux-32-debian-3.2.81-486' or '-os  windows-32-7' " << std::endl;
        return false;
    }
    else if (panda_os_familyno == OS_LINUX) {

#if defined(TARGET_I386)
#if !defined(TARGET_X86_64)
        std::cerr << PANDA_MSG "using profile for linux x86 32-bit" << std::endl;
        syscalls_profile = &profiles[PROFILE_LINUX_X86];
#else
        std::cerr << PANDA_MSG "using profile for linux x64 64-bit" << std::endl;
        syscalls_profile = &profiles[PROFILE_LINUX_X64];
#endif
#endif
#if defined(TARGET_ARM)
#if !defined(TARGET_AARCH64)
        std::cerr << PANDA_MSG "using profile for linux arm" << std::endl;
        syscalls_profile = &profiles[PROFILE_LINUX_ARM];
#else
        std::cerr << PANDA_MSG "using profile for linux aarch64" << std::endl;
        syscalls_profile = &profiles[PROFILE_LINUX_AARCH64];
#endif
#endif
#if defined(TARGET_MIPS)
        std::cerr << PANDA_MSG "using profile for linux mips" << std::endl;
        syscalls_profile = &profiles[PROFILE_LINUX_MIPS];
#endif
    }
    else if (panda_os_familyno == OS_WINDOWS) {
        if (panda_os_bits != 32) {
            std::cerr << PANDA_MSG "no support for 64-bit windows" << std::endl;
            return false;
        }
#if defined(TARGET_I386)
        if (0 == strcmp(panda_os_variant, "xpsp2")) {
            std::cerr << PANDA_MSG "using profile for windows sp2 x86 32-bit" << std::endl;
            syscalls_profile = &profiles[PROFILE_WINDOWS_XPSP2_X86];
        }
        if (0 == strcmp(panda_os_variant, "xpsp3")) {
            std::cerr << PANDA_MSG "using profile for windows sp3 x86 32-bit" << std::endl;
            syscalls_profile = &profiles[PROFILE_WINDOWS_XPSP3_X86];
        }
        if (0 == strcmp(panda_os_variant, "7")) {
            std::cerr << PANDA_MSG "using profile for windows 7 x86 32-bit" << std::endl;
            syscalls_profile = &profiles[PROFILE_WINDOWS_7_X86];
        }
        if (0 == strcmp(panda_os_variant, "2000")) {
            std::cerr << PANDA_MSG "using profile for windows 2000 x86 32-bit" << std::endl;
            syscalls_profile = &profiles[PROFILE_WINDOWS_2000_X86];
        }
#endif
    } else if (panda_os_familyno == OS_FREEBSD) {
#if defined(TARGET_X86_64)
    std::cerr << PANDA_MSG "using profile for freebsd x64 64-bit" << std::endl;
    syscalls_profile = &profiles[PROFILE_FREEBSD_X64];
#else
    std::cerr << PANDA_MSG "ERROR: using profile for freebsd x86 32-bit not yet supported!" << std::endl;
    //syscalls_profile = &profiles[PROFILE_FREEBSD_X86];
    return false;
#endif
    }

    // make sure a system calls profile has been loaded
    if(!syscalls_profile){
        std::cerr << PANDA_MSG "ERROR Couldn't find a syscall profile for the specified OS" << std::endl;
        return false;
    }

    // parse arguments and initialize callbacks & info api
    panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);

    panda_cb pcb;
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    pcb.before_block_exec = tb_check_syscall_return;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    // load system call info
    if (panda_parse_bool_opt(plugin_args, "load-info", "Load systemcall information for the selected os.")) {
        if (load_syscall_info() < 0) return false;
    }

#if defined(SYSCALL_RETURN_DEBUG)
    assert((syscall_info != NULL) && "syscall return debugging requires loading syscall info");
#endif

    // done parsing arguments
    panda_free_args(plugin_args);
#else //not x86/arm/mips
    fprintf(stderr,"The syscalls plugin is not currently supported on this platform.\n");
    return false;
#endif // x86/arm/mips
    return true;
}

void uninit_plugin(void *self) {
    //(void) self;
#ifdef DEBUG
    std::cout << PANDA_MSG "DEBUG syscall count per asid:";
    for(const auto &asid_count : syscallCounter){
        std::cout << asid_count.first << "=" << asid_count.second <<", ";
    }
    std::cout<< std::endl;
    if(impossibleToReadPCs){
        std::cout << PANDA_MSG "DEBUG some instructions couldn't be read on insn_exec: " << impossibleToReadPCs << std::endl;
    }
#endif
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
