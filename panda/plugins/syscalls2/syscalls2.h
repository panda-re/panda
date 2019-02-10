#pragma once
#include <map>
typedef struct CPUState CPUState;
typedef struct syscall_ctx syscall_ctx_t;
typedef std::map<std::pair<target_ptr_t, target_ptr_t>, syscall_ctx_t> context_map_t;
extern context_map_t running_syscalls;

// grep -hE '^.*syscall_(enter|return)_switch_[^(]*\(' *.cpp | sed 's/ {$/;/' >> syscalls2.h
void syscall_enter_switch_linux_arm(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_linux_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_2000_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_7_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_xpsp2_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_xpsp3_x86(CPUState *cpu, target_ptr_t pc);
void syscall_return_switch_linux_arm(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *rp);
void syscall_return_switch_linux_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *rp);
void syscall_return_switch_windows_2000_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *rp);
void syscall_return_switch_windows_7_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *rp);
void syscall_return_switch_windows_xpsp2_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *rp);
void syscall_return_switch_windows_xpsp3_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *rp);

