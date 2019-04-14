/*!
 * @file osi_pse.cpp
 * @brief Process-level events using the osi plugin.
 *
 * @author Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/common.h"

// osi plugin
#include "osi/osi_types.h"
#include "osi/os_intro.h"
#include "osi/osi_ext.h"

// syscalls2 plugin
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi_pse.h"
#include "osi_pse_generic.h"

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
bool init_osi_pse_linux(void *);
void uninit_osi_pse_linux(void *);
PPP_CB_EXTERN(on_process_start)
PPP_CB_EXTERN(on_process_end)
}

GArray *handles, *handles_prev;

/** @brief Dumps the handles contained in \p a */
static inline void prochandles_dump(GArray *a) {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
    for (int i=0; i<a->len; i++) {
        OsiProcHandle *h = &g_array_index(a, OsiProcHandle, i);
        LOG_INFO("%3d\t" TARGET_PTR_FMT "\t" TARGET_PTR_FMT, i, h->taskd, h->asid);
    }
#endif
}

/** @brief Dumps processes using the handles contained in \p a */
static inline void procs_dump(CPUState *cpu, GArray *a) {
#if PANDA_LOG_LEVEL >= PANDA_LOG_DEBUG
    for (int i = 0; i < a->len; i++) {
        OsiProcHandle *h = &g_array_index(a, OsiProcHandle, i);
        OsiProc *p = get_process(cpu, h);
        LOG_INFO("%3d\t" TARGET_PTR_FMT "\t" TARGET_PTR_FMT "\t"
                 TARGET_PID_FMT ":" TARGET_PID_FMT "\t%s",
                 i, p->taskd, p->asid, p->pid, p->ppid, p->name);
    }
#endif
}

/** @brief Function wrapper for the OsiProcHandle comparison inline. */
int prochandle_cmp_f(gconstpointer a, gconstpointer b) {
    return prochandle_cmp_i(a, b);
}


/**
 * @brief TBA
 */
int asid_changed(CPUState *cpu, target_ptr_t asid_old, target_ptr_t asid_new) {
    static uint32_t UNUSED(n_asid_changed);
    //LOG_DEBUG("ASID_CHANGED\t" TARGET_PTR_FMT "\t" TARGET_PTR_FMT, asid_old, asid_new);
    //return 0;

    handles_prev = handles;
    handles = get_process_handles(cpu);
    assert(handles != NULL && handles->len > 0);
    g_array_sort(handles, prochandle_cmp_f);

    LOG_DEBUG("---%5d--------------------------------", n_asid_changed++);
    //prochandles_dump(handles);
    procs_dump(cpu, handles);
    g_array_free(handles_prev, true);
    return 0;

    uint32_t i = 0;
    uint32_t j = 0;
    OsiProcHandle *hc = NULL;
    OsiProcHandle *hp = NULL;

    if (handles_prev == NULL) goto first_time;

    // Calculate two-way diff. We prefer calculating this ourselves
    // because we do it in one run.
    // Using std::set_difference() would require two runs.
    hc = &g_array_index(handles, OsiProcHandle, 0);
    hp = &g_array_index(handles_prev, OsiProcHandle, 0);
    while (i < handles->len && j < handles_prev->len) {
        int32_t cmp = prochandle_cmp_i(hc, hp);
        if (cmp == 0) {
#if 0
            if (!prochandle_asid_eq(hc, hp)) {
                PPP_RUN_CB(on_process_asid_update, cpu, hp, hc);
            }
#endif
            hc = &g_array_index(handles, OsiProcHandle, ++i);
            hp = &g_array_index(handles_prev, OsiProcHandle, ++j);
            continue;
        }
        else if (cmp < 0) {
            // add hc to started - is task ready to be read?
            // how many times is this run? (we expect one per asid_changed)
            PPP_RUN_CB(on_process_start, cpu, hc);
            hc = &g_array_index(handles, OsiProcHandle, ++i);
            continue;
        }
        else {
            // add hp to finished - is task still readable?
            // how many times is this run? (we expect one per asid_changed)
            PPP_RUN_CB(on_process_end, cpu, hp);
            hp = &g_array_index(handles_prev, OsiProcHandle, ++j);
            continue;
        }
    }
    while (i < handles->len) {
        PPP_RUN_CB(on_process_start, cpu, hc);
        hc = &g_array_index(handles, OsiProcHandle, ++i);
    }
    while (j < handles_prev->len) {
        PPP_RUN_CB(on_process_end, cpu, hp);
        hp = &g_array_index(handles_prev, OsiProcHandle, ++j);
    }

    // clear handles from previous iteration
    g_array_free(handles_prev, true);
    handles_prev = NULL;
    return 0;

first_time:
    hc = &g_array_index(handles, OsiProcHandle, 0);
    while (i < handles->len) {
        PPP_RUN_CB(on_process_start, cpu, hc);
        hc = &g_array_index(handles, OsiProcHandle, ++i);
    }
    return 0;
}

bool init_osi_pse_generic(void *self) {
    // set panda callbacks
    panda_cb pcb;
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    return true;
}

void uninit_osi_pse_generic(void *self) {
    CPUState *cpu = first_cpu;
    uint32_t i = 0;
    OsiProcHandle *hc = NULL;

    hc = &g_array_index(handles, OsiProcHandle, 0);
    while (i < handles->len) {
        PPP_RUN_CB(on_process_end, cpu, hc);
        hc = &g_array_index(handles, OsiProcHandle, ++i);
    }

    g_array_free(handles, true);
    handles = NULL;
    LOG_INFO(PLUGIN_NAME " cleanup complete.");
}


/* vim:set tabstop=4 softtabstop=4 expandtab: */
