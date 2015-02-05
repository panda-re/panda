/*!
 * @file osi_linux.cpp
 * @brief PANDA Operating System Introspection for Linux.
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright   This work is licensed under the terms of the GNU GPL, version 2.
 *              See the COPYING file in the top-level directory. 
 */
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../osi/osi_types.h"
#include "../osi/os_intro.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "utils/kernelinfo/kernelinfo.h"    /* must come after cpu.h, glib.h */
#include "osi_linux.h"                      /* must come after kernelinfo.h */
}


/*
 * Functions interfacing with QEMU/PANDA should be linked as C.
 * C++ function name mangling breaks linkage.
 */
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

void on_get_current_process(CPUState *env, OsiProc **out_p);
void on_get_processes(CPUState *env, OsiProcs **out_ps);
void on_free_osiproc(OsiProc *p);
void on_free_osiprocs(OsiProcs *ps);
void on_get_libraries(CPUState *env, OsiProc *p, OsiModules **out_ms);
void on_free_osimodules(OsiModules *ms);
}

struct kernelinfo ki;
int panda_memory_errors;

/**
 * @brief Turns on/off standalone testing mode.
 */
#define OSI_LINUX_TEST 0

/* ******************************************************************
 Helpers
****************************************************************** */

/**
 * @brief Fills an OsiProc struct.
 */
static void fill_osiproc(CPUState *env, OsiProc *p, PTR task_addr) {
    p->offset = task_addr;  // XXX: Not sure what this is. Storing task_addr here seems logical.
    p->name = get_name(env, task_addr, p->name);
    panda_memory_errors = 0;
    p->asid = get_pgd(env, task_addr);
    p->pages = NULL; // OsiPage - TODO
    p->pid = get_pid(env, task_addr);
    p->ppid = get_real_parent_pid(env, task_addr);

#if (OSI_LINUX_TEST)
    LOG_INFO(TARGET_FMT_lx ":%d:%d:" TARGET_FMT_lx ":%s", task_addr, (int)p->ppid, (int)p->pid, p->asid, p->name);
#endif
}

/**
 * @brief Fills an OsiModule struct.
 */
static void fill_osimodule(CPUState *env, OsiModule *m, PTR vma_addr) {
    target_ulong vma_start, vma_end;
    PTR vma_vm_file;
    PTR vma_dentry;
    PTR mm_addr, start_brk, brk, start_stack;

    vma_start = get_vma_start(env, vma_addr);
    vma_end = get_vma_end(env, vma_addr);
    vma_vm_file = get_vma_vm_file(env, vma_addr);

    // Fill everything but m->name and m->file.
    m->offset = vma_addr;   // XXX: Not sure what this is. Storing vma_addr here seems logical.
    m->base = vma_start;
    m->size = vma_end - vma_start;

    if (vma_vm_file != (PTR)NULL) {     // Memory area is mapped from a file.
        vma_dentry = get_vma_dentry(env, vma_addr);
        m->file = read_dentry_name(env, vma_dentry, NULL, 1);
        m->name = g_strrstr (m->file, "/");
        if (m->name != NULL) m->name = g_strdup(m->name + 1);
    }
    else {                              // Other memory areas.
        mm_addr = get_vma_vm_mm(env, vma_addr);
        start_brk = get_mm_start_brk(env, mm_addr);
        brk = get_mm_brk(env, mm_addr);
        start_stack = get_mm_start_stack(env, mm_addr);

        m->file = NULL;
        if (vma_start <= start_brk && vma_end >= brk) {
            m->name = g_strdup("[heap]");
        }
        else if (vma_start <= start_stack && vma_end >= start_stack) {
            m->name = g_strdup("[stack]");
        }
        else {
            m->name = g_strdup("[???]");
        }
    }

#if (OSI_LINUX_TEST)
    LOG_INFO(TARGET_FMT_lx ":" TARGET_FMT_lx ":" TARGET_FMT_ld "p:%s:%s",
        m->offset, m->base, NPAGES(m->size), m->name, m->file
    );
#endif
}


                                                                                                                    
/* ******************************************************************
 PPP Callbacks
****************************************************************** */

/**
 * @brief PPP callback to retrieve current process info for the running OS.
 */
void on_get_current_process(CPUState *env, OsiProc **out_p) {
    OsiProc *p;
    PTR ts;
    
    p = (OsiProc *)g_malloc0(sizeof(OsiProc));
    ts = get_task_struct(env, (_ESP & THREADINFO_MASK));
    fill_osiproc(env, p, ts);

    *out_p = p;
}

/**
 * @brief PPP callback to retrieve process list from the running OS.
 */
void on_get_processes(CPUState *env, OsiProcs **out_ps) {
    PTR ts_first, ts_current;
    OsiProcs *ps;
    OsiProc *p;
    uint32_t ps_capacity = 16;

    ts_first = ts_current = get_task_struct(env, (_ESP & THREADINFO_MASK));
    if (ts_current == (PTR)NULL) goto error0;

    // When thread_group points to itself, the task_struct belongs to a thread
    // (see kernel_structs.md for details). This will trigger an infinite loop
    // in the traversal loop.
    // Following next will lead us to a task_struct belonging to a process and
    // help avoid the condition.
    if (ts_current+ki.task.thread_group_offset != get_thread_group(env, ts_current)) {
        ts_first = ts_current = get_task_struct_next(env, ts_current);
    }

    ps = (OsiProcs *)g_malloc0(sizeof(OsiProcs));
    ps->proc = g_new(OsiProc, ps_capacity);
    do {
        if (ps->num == ps_capacity) {
            ps_capacity *= 2;
            ps->proc = g_renew(OsiProc, ps->proc, ps_capacity);
        }

        p = &ps->proc[ps->num++];

        // Garbage in p->name will cause fill_osiproc() to segfault.
        memset(p, 0, sizeof(OsiProc));
        fill_osiproc(env, p, ts_current);

        ts_current = get_task_struct_next(env, ts_current);
    } while(ts_current != (PTR)NULL && ts_current != ts_first);

    // memory read error
    if (ts_current == (PTR)NULL) goto error1;

    *out_ps = ps;
    return;

error1:
    do {
        ps->num--;
        g_free(ps->proc[ps->num].name);
    } while (ps->num != 0);
    g_free(ps->proc);
    g_free(ps);
error0:
    *out_ps = NULL;
    return;
}

/**
 * @brief PPP callback to retrieve OsiModules from the running OS.
 *
 * Current implementation returns all the memory areas  mapped by the
 * process and the files they were mapped from. Libraries that have
 * many mappings will appear multiple times.
 *
 * @todo Remove duplicates from results.
 */
void on_get_libraries(CPUState *env, OsiProc *p, OsiModules **out_ms) {
    PTR ts_first, ts_current;
    target_ulong current_pid;
    OsiModules *ms;
    OsiModule *m;
    uint32_t ms_capacity = 16;

    PTR vma_first, vma_current;

    // Find the process with the indicated pid.
    ts_first = ts_current =  get_task_struct(env, (_ESP & THREADINFO_MASK));
    if (ts_current == (PTR)NULL) goto error0;

    do {
        if ((current_pid = get_pid(env, ts_current)) == p->pid) break;
        ts_current = get_task_struct_next(env, ts_current);
    } while(ts_current != (PTR)NULL && ts_current != ts_first);

    // memory read error or process not found
    if (ts_current == (PTR)NULL || current_pid != p->pid) goto error0;

    // Read the module info for the process.
    vma_first = vma_current = get_vma_first(env, ts_current);
    if (vma_current == (PTR)NULL) goto error0;

    ms = (OsiModules *)g_malloc0(sizeof(OsiModules));
    ms->module = g_new(OsiModule, ms_capacity);
    do {
        if (ms->num == ms_capacity) {
            ms_capacity *= 2;
            ms->module = g_renew(OsiModule, ms->module, ms_capacity);
        }

        m = &ms->module[ms->num++];
        memset(m, 0, sizeof(OsiModule));
        fill_osimodule(env, m, vma_current);

        vma_current = get_vma_next(env, vma_current);
    } while(vma_current != (PTR)NULL && vma_current != vma_first);

    *out_ms = ms;
    return;

error0:
    *out_ms = NULL;
    return;
}

/**
 * @brief PPP callback to free memory allocated for an OsiProc struct.
 */
void on_free_osiproc(OsiProc *p) {
    if (p == NULL) return;
    g_free(p->name);
    g_free(p);
    return;
}

/**
 * @brief PPP callback to free memory allocated for an OsiProcs struct.
 */
void on_free_osiprocs(OsiProcs *ps) {
    uint32_t i;

    if (ps == NULL) return;

    for (i=0; i< ps->num; i++) {
        g_free(ps->proc[i].name);
    }
    g_free(ps->proc);
    g_free(ps);
    return;
}

/**
 * @brief PPP callback to free memory allocated for an OsiModules struct.
 */
void on_free_osimodules(OsiModules *ms) {
    uint32_t i;

    if (ms == NULL) return;

    for (i=0; i< ms->num; i++) {
        g_free(ms->module[i].name);
        g_free(ms->module[i].file);
    }
    g_free(ms->module);
    g_free(ms);
    return;
}



/* ******************************************************************
 Testing functions
****************************************************************** */
#if (OSI_LINUX_TEST)
/**
 * @brief Fills an OsiProc struct.
 */
int vmi_pgd_changed(CPUState *env, target_ulong oldval, target_ulong newval) {
    OsiProcs *ps;
    OsiModules *ms;
    uint32_t i;

    if (!_IN_KERNEL) {
        // This shouldn't ever happen, as PGD is updated only in kernel mode.
        LOG_ERR("Can't do introspection in user mode.");
        goto error;
    }

    LOG_INFO("------------------------------------------------");
    on_get_processes(env, &ps);
    for (i=0; i< ps->num; i++) {
        on_get_libraries(env, &ps->proc[i], &ms);
        on_free_osimodules(ms);
    }
    on_free_osiprocs(ps);
    LOG_INFO("------------------------------------------------");
    
    return 0;

error:
    return -1;
}
#endif



/* ******************************************************************
 Plugin Initialization/Cleanup
****************************************************************** */

/**
 * @brief Initializes plugin.
 */
bool init_plugin(void *self) {
#if defined(TARGET_I386) || defined(TARGET_ARM)
#if (OSI_LINUX_TEST)
    panda_cb pcb = { .after_PGD_write = vmi_pgd_changed };
#endif

    // Read the name of the kernel configuration to use.
    panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
    char *kconf_file = g_strdup(panda_parse_string(plugin_args, "kconf_file", DEFAULT_KERNELINFO_FILE));
    char *kconf_group = g_strdup(panda_parse_string(plugin_args, "kconf_group", DEFAULT_KERNELINFO_GROUP));
    panda_free_args(plugin_args);

    // Load kernel offsets.
    if (read_kernelinfo(kconf_file, kconf_group, &ki) != 0) {
        LOG_ERR("Failed to read kernel info from group \"%s\" of file \"%s\".", kconf_group, kconf_file);
        goto error;
    }
    LOG_INFO("Read kernel info from group \"%s\" of file \"%s\".", kconf_group, kconf_file);
    g_free(kconf_file);
    g_free(kconf_group);

#if (OSI_LINUX_TEST)
    panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);
#else
    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_free_osiproc, on_free_osiproc);
    PPP_REG_CB("osi", on_free_osiprocs, on_free_osiprocs);
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_free_osimodules, on_free_osimodules);
#endif
    
    LOG_INFO(PLUGIN_NAME " initialization complete.");
    return true;
#else
    goto error;
#endif

error:
    return false;
}

/**
 * @brief Plugin cleanup.
 */
void uninit_plugin(void *self) {
#if defined(TARGET_I386) || defined(TARGET_ARM)
    // Nothing to do...
#endif
    return;
}


