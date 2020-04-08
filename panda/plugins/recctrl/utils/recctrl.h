/*!
 * @file recctrl.h
 * @brief Common definitions for recctrl plugin and utility.
 */
#pragma once

/** @brief Magic code to use in cpuid hypercall. */
#define RECCTRL_MAGIC 0x666

/** @brief Maximum length for replay name. */
#define RECCTRL_RNAME_MAX 128

/** @brief Op-mode codes for the recctrl hypercall. */
typedef enum {
    RECCTRL_ACT_TOGGLE = -100,
    RECCTRL_ACT_SESSION_OPEN = 100,
    RECCTRL_ACT_SESSION_CLOSE = 200
} recctrl_action_t;

/** @brief Return codes for the recctrl hypercall. */
typedef enum {
    RECCTRL_RET_ERROR = -1,
    RECCTRL_RET_NOOP = 0,
    RECCTRL_RET_START,
    RECCTRL_RET_STOP
} recctrl_ret_t;

/* vim:set tabstop=4 softtabstop=4 expandtab: */
