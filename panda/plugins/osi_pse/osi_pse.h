#pragma once
#include "panda/debug.h"

#define ASID0 ((target_ptr_t)-1) /**< Invalid ASID value. Also used by (most) linux kernel processes. */

#define PH_FMT  TARGET_PTR_FMT " " TARGET_PTR_FMT
#if 0
#define PH_PARGS(h) (h)->taskd, (h)->asid
#define PH_ARGS(h) (h).taskd, (h).asid
#else
#define PH_PARGS(h) (h)->asid, (h)->taskd
#define PH_ARGS(h) (h).asid, (h).taskd
#endif

#define LOG_DEBUG_MSGPROC(msg, p) LOG_DEBUG("(dbg) " msg \
        " (pid=" TARGET_PID_FMT \
        " asid=" TARGET_PTR_FMT \
        " taskd=" TARGET_PTR_FMT ")", \
        (p).pid, (p).handle.asid, (p).handle.taskd)

typedef struct CPUState CPUState;

typedef void (*on_process_start_t)(CPUState *, const OsiProcHandle *);
typedef void (*on_process_end_t)(CPUState *, const OsiProcHandle *);

/* vim:set tabstop=4 softtabstop=4 expandtab: */
