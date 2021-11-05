#pragma once
#include <map>
#include <vector>
typedef struct CPUState CPUState;
typedef struct syscall_ctx syscall_ctx_t;
// typedef std::map<std::pair<target_ptr_t, target_ptr_t>, syscall_ctx_t> context_map_t;
typedef std::map<target_ptr_t,std::vector<syscall_ctx_t>> context_map_t;
extern context_map_t running_syscalls;

#define MAX_CTX_PER_ASID 30

extern void (*hooks_add_hook)(struct hook*);
void syscall_return(CPUState *cpu, TranslationBlock* tb);

// In generated, run the following to get this list
// grep -hE '^.*syscall_(enter|return)_switch_[^(]*\(' *.cpp | sed 's/ {$/;/'
void syscall_enter_switch_freebsd_x64(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_linux_arm64(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_linux_arm(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_linux_mips(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_linux_x64(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_linux_x86(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_windows_2000_x86(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_windows_7_x86(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_windows_xpsp2_x86(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_enter_switch_windows_xpsp3_x86(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_return_switch_freebsd_x64(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_linux_arm64(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_linux_arm(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_linux_mips(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_linux_x64(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_linux_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_windows_2000_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_windows_7_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_windows_xpsp2_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_windows_xpsp3_x86(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);

// You'll need to also add the freebsd ones which grep won't get
void syscall_enter_switch_freebsd_x64(CPUState *cpu, target_ptr_t pc, int static_callno);
void syscall_return_switch_freebsd_x64(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
void syscall_return_switch_freebsd_x64(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx);
