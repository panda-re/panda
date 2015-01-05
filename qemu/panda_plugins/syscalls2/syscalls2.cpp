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

extern "C" {
#define __STDC_FORMAT_MACROS
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_common.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include <stdio.h>
#include <stdlib.h>
}

#include <cassert>
#include <functional>
#include <string>
#include <map>
#include <algorithm>
#include <memory>

#include "syscalls2.h"

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

void registerExecPreCallback(void (*callback)(CPUState*, target_ulong));

}

enum ProfileType { PROFILE_LINUX_X86, PROFILE_LINUX_ARM, PROFILE_WINDOWS7_X86, PROFILE_LAST} ;

ProfileType syscalls_profile;

// Reinterpret the ulong as a long. Arch and host specific.
target_long get_return_val(CPUState *env){
#if defined(TARGET_I386)
    return static_cast<target_long>(env->regs[R_EAX]);
#elif defined(TARGET_ARM)
    return static_cast<target_long>(env->regs[0]);
#else
#error "Not Implemented"
#endif

}

target_ulong mask_retaddr_to_pc(target_ulong retaddr){
    target_ulong mask = std::numeric_limits<target_ulong>::max() -1;
    return retaddr & mask;
}

// Return address calculations
target_ulong calc_retaddr_windows7_x86(CPUState* env, target_ulong pc) {
#if defined(TARGET_I386)
    target_ulong retaddr = 0;
    panda_virtual_memory_rw(env, EDX, (uint8_t *) &retaddr, 4, false);
    return retaddr;
#else
    // shouldn't happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_x86(CPUState* env, target_ulong pc) {
#if defined(TARGET_I386)
    return pc+11;
#else
    // shouldn't happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr_linux_arm(CPUState* env, target_ulong pc) {
#if defined(TARGET_ARM)
    // Normal syscalls: return addr is stored in LR
    // Except that we haven't run the SWI instruction yet! LR is where libc will return to!
    //return mask_retaddr_to_pc(env->regs[14]);

    // Fork, exec
    uint8_t offset = 0;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
    return mask_retaddr_to_pc(pc + offset);
#else
    // shouldnt happen
    assert (1==0);
#endif
}

target_ulong calc_retaddr(CPUState* env, target_ulong pc){
    switch (syscalls_profile) {
    case PROFILE_LINUX_X86:
        return calc_retaddr_linux_x86(env, pc);
        break;
    case PROFILE_LINUX_ARM:
        return calc_retaddr_linux_arm(env, pc);
        break;
    case PROFILE_WINDOWS7_X86:
        return calc_retaddr_windows7_x86(env, pc);
        break;
    default:
        assert (1==0);
    }
    assert (1==0);
    return 0;
}

// Argument getting (at syscall entry)
uint32_t get_linux_x86_argnum(CPUState *env, uint32_t argnum) {
#if defined(TARGET_I386)
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

static uint32_t get_win_syscall_arg(CPUState* env, int nr) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t arg = 0;
    panda_virtual_memory_rw(env, env->regs[R_EDX] + 8 + (4*nr),
                            (uint8_t *) &arg, 4, false);
    return arg;
#endif
    return 0;
}

target_ulong get_32 (CPUState *env, uint32_t argnum) {
    target_ulong ret;
    
    switch (syscalls_profile) {
    case PROFILE_LINUX_X86:
        assert (argnum < 6);
        ret = (target_ulong) get_linux_x86_argnum(env, argnum);
        break;
    case PROFILE_LINUX_ARM:
        assert (argnum < 7);
        ret =  (target_ulong) env->regs[argnum];
        break;
    case PROFILE_WINDOWS7_X86:
        ret = (target_ulong) get_win_syscall_arg(env, argnum);
        break;
    default:
        assert (1==0);
    }
    return ret;
}

uint32_t get_pointer(CPUState *env, uint32_t argnum) {
    return get_32(env, argnum);
}

int32_t get_s32(CPUState *env, uint32_t argnum) {
    return (int32_t) get_32(env, argnum);
}

uint64_t get_64(CPUState *env, uint32_t argnum) {
    uint64_t ret;
    switch (syscalls_profile) {
    case PROFILE_LINUX_X86:
        assert (argnum < 6);
        ret = (((uint64_t) get_linux_x86_argnum(env, argnum)) << 32) | (get_linux_x86_argnum(env, argnum));
        break;
    case PROFILE_LINUX_ARM:
        assert (argnum < 7);
        ret = (((uint64_t) env->regs[argnum]) << 32) | (env->regs[argnum+1]);
        break;
    case PROFILE_WINDOWS7_X86:
        assert (1==0);
        break;
    default:
        assert (1==0);
    }
    return ret;
}

// Argument getting (at syscall return)
static uint32_t get_win_syscall_return_arg(CPUState* env, int nr) {
#if defined(TARGET_I386)
    // At sysenter on Windows7, args start at EDX+8
    uint32_t arg = 0;
    panda_virtual_memory_rw(env, ESP + 4 + (4*nr),
                            (uint8_t *) &arg, 4, false);
    return arg;
#endif
    return 0;
}

target_ulong get_return_32 (CPUState *env, uint32_t argnum) {
    target_ulong ret;
    
    switch (syscalls_profile) {
    case PROFILE_LINUX_X86:
        assert (argnum < 6);
        ret = (target_ulong) get_linux_x86_argnum(env, argnum);
        break;
    case PROFILE_LINUX_ARM:
        assert (argnum < 7);
        ret =  (target_ulong) env->regs[argnum];
        break;
    case PROFILE_WINDOWS7_X86:
        ret = (target_ulong) get_win_syscall_return_arg(env, argnum);
        break;
    default:
        assert (1==0);
    }
    return ret;
}

uint32_t get_return_pointer(CPUState *env, uint32_t argnum) {
    return get_return_32(env, argnum);
}

int32_t get_return_s32(CPUState *env, uint32_t argnum) {
    return (int32_t) get_return_32(env, argnum);
}

uint64_t get_return_64(CPUState *env, uint32_t argnum) {
    uint64_t ret;
    switch (syscalls_profile) {
    case PROFILE_LINUX_X86:
        assert (argnum < 6);
        ret = (((uint64_t) get_linux_x86_argnum(env, argnum)) << 32) | (get_linux_x86_argnum(env, argnum));
        break;
    case PROFILE_LINUX_ARM:
        assert (argnum < 7);
        ret = (((uint64_t) env->regs[argnum]) << 32) | (env->regs[argnum+1]);
        break;
    case PROFILE_WINDOWS7_X86:
        assert (1==0);
        break;
    default:
        assert (1==0);
    }
    return ret;
}

std::vector<void (*)(CPUState*, target_ulong)> preExecCallbacks;

void registerExecPreCallback(void (*callback)(CPUState*, target_ulong)){
    preExecCallbacks.push_back(callback);
}

// always return to same process
static std::map < std::pair < target_ulong, target_ulong >, ReturnPoint > returns; 

void appendReturnPoint(ReturnPoint &rp){
    returns[std::make_pair(rp.retaddr,rp.proc_id)] = rp;
}


static int returned_check_callback(CPUState *env, TranslationBlock* tb){
    // check if any of the internally tracked syscalls has returned
    // only one should be at its return point for any given basic block
    std::pair < target_ulong, target_ulong > ret_key = std::make_pair(tb->pc, panda_current_asid(env));
    if (returns.count(ret_key) != 0) {
        ReturnPoint &retVal = returns[ret_key];
        switch (syscalls_profile) {
        case PROFILE_LINUX_X86:
            syscall_return_switch_linux_x86(env, tb->pc, retVal.ordinal);
            break;
        case PROFILE_LINUX_ARM:
            syscall_return_switch_linux_arm(env, tb->pc, retVal.ordinal);
            break;
        case PROFILE_WINDOWS7_X86:
            syscall_return_switch_windows7_x86(env, tb->pc, retVal.ordinal);
            break;
        default:
            assert (1==0);
        }
        // used by remove_if to delete from returns list those values
        // that have been processed
        //        retVal.retaddr = retVal.proc_id = 0;
        returns.erase(ret_key);
    }
    
    //    returns.remove_if(is_empty);
    //    return invalidate;
    return false;
}


// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
    // run any code we need to update our state
    for(const auto callback : preExecCallbacks){
        callback(env, pc);
    }    
    switch (syscalls_profile) {
    case PROFILE_LINUX_X86:
        syscall_enter_switch_linux_x86(env, pc);
        break;
    case PROFILE_LINUX_ARM:
        syscall_enter_switch_linux_arm(env, pc);
        break;
    case PROFILE_WINDOWS7_X86:
        syscall_enter_switch_windows7_x86(env, pc);
        break;
    default:
        assert (1==0);
    }
    return 0;
}



// Check if the instruction is sysenter (0F 34)
bool translate_callback(CPUState *env, target_ulong pc) {
#if defined(TARGET_I386)
    unsigned char buf[2] = {};
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05)
    if (buf[0]== 0x0F && buf[1] == 0x05) {
        return true;
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0]== 0x0F && buf[1] == 0x34) {
        return true;
    }
    else {
        return false;
    }
#elif defined(TARGET_ARM)
    unsigned char buf[4] = {};

    // Check for ARM mode syscall
    if(env->thumb == 0) {
        panda_virtual_memory_rw(env, pc, buf, 4, 0);
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
        panda_virtual_memory_rw(env, pc, buf, 2, 0);
        // check for Thumb mode syscall
        if (buf[1] == 0xDF && buf[0] == 0){
            return true;
        }
    }
    return false;
#endif
}


extern "C" {

panda_arg_list *args;

bool init_plugin(void *self) {

    printf("Initializing plugin syscalls2\n");

    args = panda_get_args("syscalls");
    const char *profile_name = panda_parse_string(args, "profile", "linux_x86");
    if (0 == strncmp(profile_name, "linux_x86", 8)) {
        syscalls_profile = PROFILE_LINUX_X86;
    }
    else if (0 == strncmp(profile_name, "linux_arm", 8)) {
        syscalls_profile = PROFILE_LINUX_ARM;
    }
    else if (0 == strncmp(profile_name, "windows7_x86", 8)) {
        syscalls_profile = PROFILE_WINDOWS7_X86;
    }
    else {
        printf ("Unrecognized profile %s\n", profile_name);
        assert (1==0);
    }
// Don't bother if we're not on a supported target
#if defined(TARGET_I386) || defined(TARGET_ARM)
    panda_cb pcb;
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    //    pcb.before_block_exec_invalidate_opt = returned_check_callback;
    //   panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    pcb.before_block_exec = returned_check_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
#else
    fwrite(stderr,"The syscalls plugin is not currently supported on this platform.\n");
    return false;
#endif
    return true;
}

void uninit_plugin(void *self) {
}

}
