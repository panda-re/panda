#ifndef SYSCALLS2_H
#define SYSCALLS2_H
typedef struct CPUState CPUState;
typedef struct ReturnPoint ReturnPoint;

void syscall_return_switch_linux_arm ( CPUState *env, target_ulong pc, target_ulong ordinal, ReturnPoint &rp);
void syscall_return_switch_linux_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal, ReturnPoint &rp);
void syscall_return_switch_windows_xpsp2_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal, ReturnPoint &rp);
void syscall_return_switch_windows_xpsp3_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal, ReturnPoint &rp);
void syscall_return_switch_windows_7_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal, ReturnPoint &rp);
void syscall_return_switch_windows_2000_x86 ( CPUState *env, target_ulong pc, target_ulong ordinal, ReturnPoint &rp);

void syscall_enter_switch_linux_arm ( CPUState *env, target_ulong pc );
void syscall_enter_switch_linux_x86 ( CPUState *env, target_ulong pc );
void syscall_enter_switch_windows_xpsp2_x86 ( CPUState *env, target_ulong pc ) ;
void syscall_enter_switch_windows_xpsp3_x86 ( CPUState *env, target_ulong pc ) ;
void syscall_enter_switch_windows_7_x86 ( CPUState *env, target_ulong pc ) ;
void syscall_enter_switch_windows_2000_x86 ( CPUState *env, target_ulong pc ) ;

void appendReturnPoint(ReturnPoint& rp);
#endif
