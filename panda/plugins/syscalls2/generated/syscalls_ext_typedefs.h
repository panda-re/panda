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
#define GLOBAL_MAX_SYSCALL_ARGS 17

/**
 * @brief Maximum size for a syscall argument across all supported platforms.
 */
#define GLOBAL_MAX_SYSCALL_ARG_SIZE sizeof(uint64_t)

/**
 * @brief Holds information about an ongoing system calls. This is
 * needed in order to be able to make the system call arguments
 * available to the return callback.
 */
struct syscall_ctx {
    int no;               /**< number */
    target_ptr_t asid;    /**< calling process asid */
    target_ptr_t retaddr; /**< return address */
    uint8_t args[GLOBAL_MAX_SYSCALL_ARGS]
                [GLOBAL_MAX_SYSCALL_ARG_SIZE]; /**< arguments */
};
typedef struct syscall_ctx syscall_ctx_t;

#if defined(TARGET_ARM)
#include "syscalls_ext_typedefs_arm"
#endif
#if defined(TARGET_X86_64)
#include "syscalls_ext_typedefs_x64"
#endif
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
#include "syscalls_ext_typedefs_x86"
#endif

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
typedef void (*on_all_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_all_sys_enter2_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx);
typedef void (*on_all_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_all_sys_return2_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx);
typedef void (*on_unknown_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_unknown_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */