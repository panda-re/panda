/*!
 * @file panda/types.h
 * @brief Common PANDA data types. This header is meant for low-level
 * data types and helper functions/macros that are used across plugins.
 *
 * @note Currently, the data types defined here are meant as
 * code-readability enhancements. I.e. they make more explicit the
 * intended use of variables, rather than re-using target_ulong
 * everywhere.
 */
#pragma once
#if !defined(__cplusplus)
#include <stdbool.h>
#include <stdint.h>
#else
#include <cstdbool>
#include <cstdint>
#endif

/**
 * @brief Wrapper macro for quashing warnings for unused variables.
 */
#if defined(UNUSED)
#elif defined(__GNUC__)
#define UNUSED(x) x __attribute__((unused))
#elif defined(__LCLINT__)
#define UNUSED(x) /*@unused@*/ x
#else
#define UNUSED(x) x
#endif

#if defined(__cplusplus)
extern "C" {
#endif
#include "cpu.h"
#if defined(__cplusplus)
}
#endif

/** @brief Pointer type for the guest VM. */
typedef target_ulong target_ptr_t;

/** @brief Print format for guest VM pointers. */
#define TARGET_PTR_FMT TARGET_FMT_lx

/** @brief Type for the guest VM pids. */
typedef target_ulong target_pid_t;

/** @brief Print format for guest VM pids. */
#define TARGET_PID_FMT TARGET_FMT_lu

/* vim:set tabstop=4 softtabstop=4 expandtab: */
