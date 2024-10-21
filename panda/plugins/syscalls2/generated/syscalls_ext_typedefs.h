/*!
 * @file syscalls_ext_typedefs.h
 * @brief Definitions of types for syscalls2 callbacks.
 */
#pragma once
#include "panda/types.h"
#include "../syscalls2_info.h"

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
    bool double_return;
    int profile;
};
typedef struct syscall_ctx syscall_ctx_t;

/* Functions used to populate syscall_ctx_t structs. */
target_long get_return_val(CPUState *env, int profile);
target_ptr_t mask_retaddr_to_pc(target_ptr_t retaddr, syscall_ctx_t *);
target_ptr_t calc_retaddr(CPUState *env, syscall_ctx_t*, target_ptr_t pc);
uint32_t get_32(CPUState *env, syscall_ctx_t*, uint32_t argnum);
int32_t get_s32(CPUState *env, syscall_ctx_t*, uint32_t argnum);
uint64_t get_64(CPUState *env, syscall_ctx_t*, uint32_t argnum);
int64_t get_s64(CPUState *env, syscall_ctx_t*, uint32_t argnum);
uint32_t get_return_32(CPUState *env, syscall_ctx_t*, uint32_t argnum);
int32_t get_return_s32(CPUState *env, syscall_ctx_t*, uint32_t argnum);
uint64_t get_return_64(CPUState *env, syscall_ctx_t*, uint32_t argnum);
int64_t get_return_s64(CPUState *env, syscall_ctx_t*, uint32_t argnum);
void sysinfo_load_profile(int profile, syscall_info_t **syscall_info, syscall_meta_t **syscall_meta);

#if defined(TARGET_X86_64)
#include "syscalls_ext_typedefs_x64.h"
#endif
#if defined(TARGET_I386)
#include "syscalls_ext_typedefs_x86.h"
#endif
#if defined(TARGET_ARM) && defined(TARGET_AARCH64)
#include "syscalls_ext_typedefs_arm64.h"
#endif
#if defined(TARGET_ARM)
#include "syscalls_ext_typedefs_arm.h"
#endif
#if defined(TARGET_MIPS) && defined(TARGET_MIPS64)
#include "syscalls_ext_typedefs_mips64.h"
#endif
#if defined(TARGET_MIPS) && !defined(TARGET_MIPS64)
#include "syscalls_ext_typedefs_mips64n32.h"
#endif
#if defined(TARGET_MIPS) && !defined(TARGET_MIPS64)
#include "syscalls_ext_typedefs_mips.h"
#endif

// WIP - How can we expose these to pypanda given that they need syscall_ctx which dependes on #DEFINES
// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
PPP_CB_TYPEDEF(void, on_all_sys_enter, CPUState *cpu, target_ulong pc, target_ulong callno);
PPP_CB_TYPEDEF(void, on_all_sys_enter2, CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx);
PPP_CB_TYPEDEF(void, on_all_sys_return, CPUState *cpu, target_ulong pc, target_ulong callno);
PPP_CB_TYPEDEF(void, on_all_sys_return2, CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx);
PPP_CB_TYPEDEF(void, on_unknown_sys_enter, CPUState *cpu, target_ulong pc, target_ulong callno);
PPP_CB_TYPEDEF(void, on_unknown_sys_return, CPUState *cpu, target_ulong pc, target_ulong callno);
// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */