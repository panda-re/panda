#ifndef __SYSCALLS_COMMON_HPP
#define __SYSCALLS_COMMON_HPP

extern "C" {
// get definitions of QEMU types
#include "cpu.h"

}

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

struct ReturnPoint {
    target_ulong ordinal;
    target_ulong retaddr;
    target_ulong proc_id;
};

typedef void (*pre_exec_callback_t)(CPUState*, target_ulong);

#endif
