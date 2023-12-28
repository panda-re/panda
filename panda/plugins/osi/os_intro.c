/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <libgen.h>
#include <limits.h>
#include <stdlib.h>

// glib provides some nifty string manipulation functions
// https://developer.gnome.org/glib/stable/glib-String-Utility-Functions.html
#include <glib.h>
#include <gmodule.h>
#include <glib/gprintf.h>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "osi_types.h"
#include "osi_int_fns.h"
#include "os_intro.h"

bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_get_processes)
PPP_PROT_REG_CB(on_get_process_handles)
PPP_PROT_REG_CB(on_get_current_process)
PPP_PROT_REG_CB(on_get_current_process_handle)
PPP_PROT_REG_CB(on_get_process)
PPP_PROT_REG_CB(on_get_proc_mem)
PPP_PROT_REG_CB(on_get_modules)
PPP_PROT_REG_CB(on_get_mappings)
PPP_PROT_REG_CB(on_get_file_mappings)
PPP_PROT_REG_CB(on_get_heap_mappings)
PPP_PROT_REG_CB(on_get_stack_mappings)
PPP_PROT_REG_CB(on_get_unknown_mappings)
PPP_PROT_REG_CB(on_get_mapping_by_addr)
PPP_PROT_REG_CB(on_get_mapping_base_address_by_name)
PPP_PROT_REG_CB(on_has_mapping_prefix)
PPP_PROT_REG_CB(on_get_current_thread)
PPP_PROT_REG_CB(on_get_process_pid)
PPP_PROT_REG_CB(on_get_process_ppid)

PPP_PROT_REG_CB(on_task_change)

PPP_CB_BOILERPLATE(on_get_processes)
PPP_CB_BOILERPLATE(on_get_process_handles)
PPP_CB_BOILERPLATE(on_get_current_process)
PPP_CB_BOILERPLATE(on_get_current_process_handle)
PPP_CB_BOILERPLATE(on_get_process)
PPP_CB_BOILERPLATE(on_get_proc_mem)
PPP_CB_BOILERPLATE(on_get_modules)
PPP_CB_BOILERPLATE(on_get_mappings)
PPP_CB_BOILERPLATE(on_get_file_mappings)
PPP_CB_BOILERPLATE(on_get_heap_mappings)
PPP_CB_BOILERPLATE(on_get_stack_mappings)
PPP_CB_BOILERPLATE(on_get_unknown_mappings)
PPP_CB_BOILERPLATE(on_get_mapping_by_addr)
PPP_CB_BOILERPLATE(on_get_mapping_base_address_by_name)
PPP_CB_BOILERPLATE(on_has_mapping_prefix)
PPP_CB_BOILERPLATE(on_get_current_thread)
PPP_CB_BOILERPLATE(on_get_process_pid)
PPP_CB_BOILERPLATE(on_get_process_ppid)

PPP_CB_BOILERPLATE(on_task_change)

// The copious use of pointers to pointers in this file is due to
// the fact that PPP doesn't support return values (since it assumes
// that you will be running multiple callbacks at one site)

GArray *get_processes(CPUState *cpu) {
    GArray *p = NULL;
    PPP_RUN_CB(on_get_processes, cpu, &p);
    return p;
}

GArray *get_process_handles(CPUState *cpu) {
    GArray *p = NULL;
    PPP_RUN_CB(on_get_process_handles, cpu, &p);
    return p;
}

OsiProc *get_current_process(CPUState *cpu) {
    OsiProc *p = NULL;
    PPP_RUN_CB(on_get_current_process, cpu, &p);
    return p;
}

OsiProcHandle *get_current_process_handle(CPUState *cpu) {
    OsiProcHandle *h = NULL;
    PPP_RUN_CB(on_get_current_process_handle, cpu, &h);
    return h;
}

OsiProc *get_process(CPUState *cpu, const OsiProcHandle *h) {
    OsiProc *p = NULL;
    PPP_RUN_CB(on_get_process, cpu, h, &p);
    return p;
}

OsiProcMem *get_proc_mem(CPUState *cpu, const OsiProc *p) {
    OsiProcMem *pm = NULL;
    PPP_RUN_CB(on_get_proc_mem, cpu, p, &pm);
    return pm;
}

GArray *get_modules(CPUState *cpu) {
    GArray *m = NULL;
    PPP_RUN_CB(on_get_modules, cpu, &m);
    return m;
}

GArray *get_mappings(CPUState *cpu, OsiProc *p) {
    GArray *m = NULL;
    PPP_RUN_CB(on_get_mappings, cpu, p, &m);
    return m;
}

GArray *get_file_mappings(CPUState *cpu, OsiProc *p) {
    GArray *m = NULL;
    PPP_RUN_CB(on_get_file_mappings, cpu, p, &m);
    return m;
}

GArray *get_heap_mappings(CPUState *cpu, OsiProc *p) {
    GArray *m = NULL;
    PPP_RUN_CB(on_get_heap_mappings, cpu, p, &m);
    return m;
}

GArray *get_stack_mappings(CPUState *cpu, OsiProc *p) {
    GArray *m = NULL;
    PPP_RUN_CB(on_get_stack_mappings, cpu, p, &m);
    return m;
}

GArray *get_unknown_mappings(CPUState *cpu, OsiProc *p) {
    GArray *m = NULL;
    PPP_RUN_CB(on_get_unknown_mappings, cpu, p, &m);
    return m;
}

OsiModule *get_mapping_by_addr(CPUState *cpu, OsiProc *p,
        const target_ptr_t addr) {
    OsiModule *osiModule = NULL;
    PPP_RUN_CB(on_get_mapping_by_addr, cpu, p, addr, &osiModule);
    return osiModule;
}

target_ptr_t get_mapping_base_address_by_name(CPUState *cpu, OsiProc *p,
        const char *name) {
    target_ptr_t baseAddress = 0;
    PPP_RUN_CB(on_get_mapping_base_address_by_name, cpu, p, name, &baseAddress);
    return baseAddress;
}

bool has_mapping_prefix(CPUState *cpu, OsiProc *p, const char *prefix) {
    bool found = false;
    PPP_RUN_CB(on_has_mapping_prefix, cpu, p, prefix, &found);
    return found;
}

OsiThread *get_current_thread(CPUState *cpu) {
    OsiThread *thread = NULL;
    static OsiThread cachedThread;
    static uint64_t cachedInstructionCount;
    if((cachedInstructionCount != 0) &&
            (cachedInstructionCount == cpu->rr_guest_instr_count)) {
        thread=(OsiThread *) g_malloc(sizeof(*thread));
        if (thread == NULL) {
            return NULL;
        }
        memcpy(thread, &cachedThread, sizeof(*thread));
    } else {
        PPP_RUN_CB(on_get_current_thread, cpu, &thread);
        if (thread == NULL) {
            // Returns NULL if OSI can't find the current thread
            return NULL;
        }
        cachedInstructionCount = cpu->rr_guest_instr_count;
        memcpy(&cachedThread, thread, sizeof(cachedThread));
    }
    return thread;
}

target_pid_t get_process_pid(CPUState *cpu, const OsiProcHandle *h) {
    target_pid_t pid;
    PPP_RUN_CB(on_get_process_pid, cpu, h, &pid);
    return pid;
}

target_pid_t get_process_ppid(CPUState *cpu, const OsiProcHandle *h) {
    target_pid_t ppid;
    PPP_RUN_CB(on_get_process_ppid, cpu, h, &ppid);
    return ppid;
}

void notify_task_change(CPUState *cpu)
{
    PPP_RUN_CB(on_task_change, cpu);
}

bool in_shared_object(CPUState *cpu, OsiProc *p) {
    if (panda_in_kernel(cpu)) {
        return false;
    }

    target_ulong pc = panda_current_pc(cpu);
    GArray *mappings = get_mappings(cpu, p);

    if (mappings != NULL) {
        for (int i = 0; i < mappings->len; i++) {
            OsiModule *m = &g_array_index(mappings, OsiModule, i);
            if ((m->base <= pc) && (pc <= (m->base + m->size))) {
                // XXX: libc doesn't have a bounded string substring search? e.g. strnstr?
                // XXX: this logic hasn't been tested on the Windows OS
                if ((strcasestr(m->name, ".so") != NULL) || (strcasestr(m->name, ".dll") != NULL)) {
                    return true;
                } else {
                    return false;
                }
            }
        }
        g_array_free(mappings, true);
    }

    return false;
}

extern const char *qemu_file;

bool init_plugin(void *self) {
    // No os supplied on command line? E.g. -os linux-32-ubuntu:4.4.0-130-generic
    assert (!(panda_os_familyno == OS_UNKNOWN));

    bool disable_os_autoload;
    panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
    disable_os_autoload = panda_parse_bool_opt(plugin_args, "disable-autoload", "When set, OSI won't automatically load osi_linux/wintrospection");
    panda_free_args(plugin_args);

    if (disable_os_autoload) {
        return true;
    }

    // If not disabled_os_autoload, load OSI_linux or wintrospection (with no arguments) automatically
    if (panda_os_familyno == OS_LINUX) {
        LOG_INFO("OSI grabbing Linux introspection backend.");
        panda_require("osi_linux");
    } else if (panda_os_familyno == OS_WINDOWS) {
        LOG_INFO("OSI grabbing Windows introspection backend.");
        panda_require("wintrospection");
    }
    return true;
}

void uninit_plugin(void *self) { }

// Helper function to get a single element. Should only be used with library mode
// when g_array_index can't be used directly.
// TODO: Can these be moved to a seperate file? Do we need implementations for more types?

OsiModule* get_one_module(GArray *osimodules, unsigned int idx) {
    OsiModule *m = &g_array_index(osimodules, OsiModule, idx);
    return m;
}

// Helper function to get a single element. Should only be used with library mode
// when g_array_index can't be used directly.
OsiProc* get_one_proc(GArray *osiprocs, unsigned int idx) {
    OsiProc *m = &g_array_index(osiprocs, OsiProc, idx);
    return m;
}

void cleanup_garray(GArray *g) {
    if (g == NULL) return;
    // Maybe this should just be in panda api instead of OSI?
    // but for now we only expose GArrays via library mode with OSI
    g_array_free(g, true);
}
