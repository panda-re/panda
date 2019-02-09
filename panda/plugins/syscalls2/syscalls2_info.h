/*!
 * @file syscalls2_info.h
 * @brief Definitions for generic description of system calls.
 */
#pragma once
#if !defined(__cplusplus)
#include <stdint.h>
#else
#include <cstdint>
#endif

/**
 * @brief Meta-information about system calls.
 */
typedef struct {
    uint32_t max;
    uint32_t max_generic;
    uint32_t max_args;
} syscall_meta_t;

/**
 * @brief Type of system call argument enumeration.
 */
typedef enum {
    SYSCALL_ARG_U64 = 0x00, /**< unsigned 64bit value */
    SYSCALL_ARG_U32,        /**< unsigned 32bit value */
    SYSCALL_ARG_U16,        /**< unsigned 16bit value */
    SYSCALL_ARG_S64 = 0x10, /**< signed 64bit value */
    SYSCALL_ARG_S32,        /**< signed 32bit value */
    SYSCALL_ARG_S16,        /**< signed 16bit value */
    SYSCALL_ARG_PTR = 0x20, /**< pointer to buffer/struct */
    SYSCALL_ARG_STR         /**< C string */
} syscall_argtype_t;

/**
 * @brief System call information.
 */
typedef struct {
    int no;
    const char *name;
    int nargs;
    syscall_argtype_t *argt;
    uint8_t *argsz;
    bool noreturn;
} syscall_info_t;

#if defined(__cplusplus)
extern "C" {
#endif
/**
 * @brief Dynamically loads system call information.
 */
int load_syscall_info(void);
#if defined(__cplusplus)
}
#endif

/* vim: set tabstop=4 softtabstop=4 expandtab: */
