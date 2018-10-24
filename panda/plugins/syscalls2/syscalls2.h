#pragma once
typedef struct CPUState CPUState;
typedef struct ReturnPoint ReturnPoint;

void appendReturnPoint(ReturnPoint& rp);

// grep -hE '^.*syscall_(enter|return)_switch_[^(]*\(' *.cpp | sed 's/ {$/;/' >> syscalls2.h
void syscall_enter_switch_linux_arm(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_linux_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_2000_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_7_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_xpsp2_x86(CPUState *cpu, target_ptr_t pc);
void syscall_enter_switch_windows_xpsp3_x86(CPUState *cpu, target_ptr_t pc);
void syscall_return_switch_linux_arm(CPUState *cpu, target_ptr_t pc, int no, const ReturnPoint *rp);
void syscall_return_switch_linux_x86(CPUState *cpu, target_ptr_t pc, int no, const ReturnPoint *rp);
void syscall_return_switch_windows_2000_x86(CPUState *cpu, target_ptr_t pc, int no, const ReturnPoint *rp);
void syscall_return_switch_windows_7_x86(CPUState *cpu, target_ptr_t pc, int no, const ReturnPoint *rp);
void syscall_return_switch_windows_xpsp2_x86(CPUState *cpu, target_ptr_t pc, int no, const ReturnPoint *rp);
void syscall_return_switch_windows_xpsp3_x86(CPUState *cpu, target_ptr_t pc, int no, const ReturnPoint *rp);

