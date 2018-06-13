#ifndef __SYSCALLS_COMMON_HPP
#define __SYSCALLS_COMMON_HPP

#ifdef __cplusplus
extern "C" {
#endif
// get definitions of QEMU types
#include "cpu.h"

#ifdef __cplusplus
}
#endif


target_long get_return_val(CPUState *env);
target_ulong mask_retaddr_to_pc(target_ulong retaddr);
target_ulong calc_retaddr(CPUState* env, target_ulong pc) ;

uint32_t get_32 (CPUState *env, uint32_t argnum);
int32_t get_s32(CPUState *env, uint32_t argnum);
uint64_t get_64(CPUState *env, uint32_t argnum);
int64_t get_s64(CPUState *env, uint32_t argnum);
target_ulong get_pointer(CPUState *env, uint32_t argnum);
uint32_t get_return_32 (CPUState *env, uint32_t argnum);
int32_t get_return_s32(CPUState *env, uint32_t argnum);
uint64_t get_return_64(CPUState *env, uint32_t argnum);
int64_t get_return_s64(CPUState *env, uint32_t argnum);
target_ulong get_return_pointer(CPUState *env, uint32_t argnum);

#define SYSCALL_MAX_ARGS 32

// Params is a buffer area to hold parameters until the system call returns.
// Needed because otherwise we can't make the parameters available reliably in
// the return callback.  Has to be a dumb buffer (not type safe) because we
// don't have any way to stuff a bunch of heterogeneous types in here otherwise.
// We only have one ReturnPoint but many different function signatures.
struct ReturnPoint {
    target_ulong ordinal;
    target_ulong retaddr;
    target_ulong proc_id;
    uint8_t params[SYSCALL_MAX_ARGS][8];
};

#endif
