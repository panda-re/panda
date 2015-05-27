#ifndef __SYSCALLS_HPP
#define __SYSCALLS_HPP

#include "syscalls_common.h"

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"


}

void syscall_return_switch_linux_arm ( CPUState *env, target_ulong pc, target_ulong ordinal);
void syscall_return_switch_linux_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal);
void syscall_return_switch_windowsxp_sp2_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal);
void syscall_return_switch_windowsxp_sp3_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal);
void syscall_return_switch_windows7_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal);

void syscall_enter_switch_linux_arm ( CPUState *env, target_ulong pc );
void syscall_enter_switch_linux_x86 ( CPUState *env, target_ulong pc );
void syscall_enter_switch_windowsxp_sp2_x86 ( CPUState *env, target_ulong pc ) ;
void syscall_enter_switch_windowsxp_sp3_x86 ( CPUState *env, target_ulong pc ) ;
void syscall_enter_switch_windows7_x86 ( CPUState *env, target_ulong pc ) ;


void appendReturnPoint(ReturnPoint& rp);


#endif
