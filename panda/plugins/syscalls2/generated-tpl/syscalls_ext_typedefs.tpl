/*!
 * @file syscalls_ext_typedefs.h
 * @brief Definitions of types for syscalls2 callbacks.
 */
#pragma once
#include "panda/types.h"
#include "../syscalls2_info.h"

/* Functions used to populate syscall_ctx_t structs. */
target_long get_return_val(CPUState *env);
target_ptr_t mask_retaddr_to_pc(target_ptr_t retaddr);
target_ptr_t calc_retaddr(CPUState *env, target_ptr_t pc);
uint32_t get_32(CPUState *env, uint32_t argnum);
int32_t get_s32(CPUState *env, uint32_t argnum);
uint64_t get_64(CPUState *env, uint32_t argnum);
int64_t get_s64(CPUState *env, uint32_t argnum);
target_ptr_t get_pointer(CPUState *env, uint32_t argnum);
uint32_t get_return_32(CPUState *env, uint32_t argnum);
int32_t get_return_s32(CPUState *env, uint32_t argnum);
uint64_t get_return_64(CPUState *env, uint32_t argnum);
int64_t get_return_s64(CPUState *env, uint32_t argnum);
target_ptr_t get_return_pointer(CPUState *env, uint32_t argnum);

/**
 * @brief Maximum number of arguments for a system call across
 * all supported platforms.
 */
#define GLOBAL_MAX_SYSCALL_ARGS {{global_max_syscall_args}}

/**
 * @brief Holds information about an ongoing system calls. This is
 * needed in order to be able to make the system call arguments
 * available to the return callback.
 */
struct syscall_ctx {
    int no;               /**< system call number */
    target_ptr_t asid;    /**< asid of the process that made the system call */
    target_ptr_t retaddr; /**< return address of the system call */
    uint8_t args[GLOBAL_MAX_SYSCALL_ARGS][8]; /**< system call arguments */
};
typedef struct syscall_ctx syscall_ctx_t;

{% for arch, syscalls in syscalls_arch|dictsort -%}
#ifdef {{architectures[arch].qemu_target}}
{%- for syscall_name, syscall in syscalls|dictsort %}
typedef void (*on_{{syscall.name}}_enter_t)({{syscall.cargs_signature}});
typedef void (*on_{{syscall.name}}_return_t)({{syscall.cargs_signature}});
{%- endfor %}
#endif
{% endfor %}
typedef void (*on_all_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_all_sys_enter2_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx);
typedef void (*on_all_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_all_sys_return2_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx);
typedef void (*on_unknown_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_unknown_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
