/*!
 * @file debug.h
 * @brief Macros for better debug output.
 */
#pragma once
#if !defined(__cplusplus)
#include <stdio.h>
#else
#include <cstdio>
#endif

/**
 * @brief Macro that evaluates to the basename of the current file.
 */
#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

/**
 * @brief Name to report in messages when PLUGIN_NAME is not set.
 */
#define PANDA_CORE_NAME "core"

/**
 * @brief Prefix for the PANDA message prefix.
 */
#define PANDA_MSG_PREFIX "PANDA["

/**
 * @brief Suffix for the PANDA message prefix.
 */
#define PANDA_MSG_SUFFIX "]:"

/**
 * @brief Format for creating a PANDA message prefix with a dynamic plugin name.
 *
 * @note This comes handy in plugin initialization code, where you want to
 * report a plugin name rather than the less specific PANDA_CORE_NAME.
 */
#define PANDA_MSG_FMT PANDA_MSG_PREFIX "%s" PANDA_MSG_SUFFIX

/**
 * @brief PANDA message prefix macro.
 */
#ifdef PLUGIN_NAME
#define PANDA_MSG PANDA_MSG_PREFIX PLUGIN_NAME PANDA_MSG_SUFFIX
#else
#define PANDA_MSG PANDA_MSG_PREFIX PANDA_CORE_NAME PANDA_MSG_SUFFIX
#endif

/**
 * @brief Get a textual representation of a flag variable.
 */
#define PANDA_FLAG_STATUS(flag) ((flag) ? "ENABLED" : "DISABLED")

#if !defined(PANDA_NODEBUG)
/**
 * @brief Print the current file/line to stdout. Useful for debugging control flow issues.
 */
#define PANDALN printf("@%s:%03d\n", __FILENAME__, __LINE__)

/**
 * @brief Macro for logging error messages.
 */
#if !defined(LOG_ERROR_FILE)
#define LOG_ERROR_FILE stderr
#endif
#define LOG_ERROR(fmt, args...) fprintf(LOG_ERROR_FILE, PANDA_MSG "E:%s(%s)> " fmt "\n", __FILENAME__, __func__, ## args)

/**
 * @brief Macro for logging warning messages.
 */
#if !defined(LOG_WARN_FILE)
#define LOG_WARN_FILE stderr
#endif
#define LOG_WARN(fmt, args...)  fprintf(LOG_WARN_FILE, PANDA_MSG "W:%s(%s)> "  fmt "\n", __FILENAME__, __func__, ## args)

/**
 * @brief Macro for logging informational messages.
 */
#if !defined(LOG_INFO_FILE)
#define LOG_INFO_FILE stderr
#endif
#define LOG_INFO(fmt, args...)  fprintf(LOG_INFO_FILE, PANDA_MSG "I:%s(%s)> "  fmt "\n", __FILENAME__, __func__, ## args)
#else
#define PANDALN
#define LOG_ERROR(fmt, args...) {}
#define LOG_WARN(fmt, args...) {}
#define LOG_INFO(fmt, args...) {}
#endif

/* vim:set tabstop=4 softtabstop=4 expandtab: */
