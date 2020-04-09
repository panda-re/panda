/*!
 * @file osi_pse_generic.h
 * @brief Helpers for the generic implementation for process-level events.
 *
 * @author Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#pragma once

#define prochandle_asid(a) ((OsiProcHandle *)a)->asid
#define prochandle_task(a) ((OsiProcHandle *)a)->taskd
#define prochandle_asid_zero(a) (prochandle_asid(a) == (target_ptr_t)-1)
#define prochandle_asid_eq(a, b) (prochandle_asid(a) == prochandle_asid(b))
#define prochandle_asid_diff(a, b) (prochandle_asid(a) - prochandle_asid(b))
#define prochandle_task_eq(a, b) (prochandle_task(a) == prochandle_task(b))
#define prochandle_task_diff(a, b) (prochandle_task(a) - prochandle_task(b))

/**
 * @brief Inline for comparing OsiProcHandle structs for sorting purposes.
 *
 * We sort by task because of some linux intricacies:
 *  - linux kernel processes share asid 0xffffffff;
 *    we need to compare tasks to tell them apart anyway.
 *  - the asid of a process being destroyed is set to 0xffffffff;
 *    this will result in triggering false process start/end events.
 */
static inline int prochandle_cmp_i(gconstpointer a, gconstpointer b) {
    return prochandle_task_diff(a, b);
}

/** @brief Function wrapper for the OsiProcHandle comparison inline. */
int prochandle_cmp_f(gconstpointer a, gconstpointer b);

/* vim:set tabstop=4 softtabstop=4 expandtab: */
