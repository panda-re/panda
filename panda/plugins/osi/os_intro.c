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

// glib provides some nifty string manipulation functions
// https://developer.gnome.org/glib/stable/glib-String-Utility-Functions.html
#include <glib.h>
#include <glib/gprintf.h>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "osi_types.h"
#include "osi_int_fns.h"
#include "os_intro.h"
#ifdef OSI_PROC_EVENTS
#include "osi_proc_events.h"
#endif

bool init_plugin(void *);
void uninit_plugin(void *);
#ifdef OSI_PROC_EVENTS
int asid_changed(CPUState *, target_ulong, target_ulong);
#endif

PPP_PROT_REG_CB(on_get_processes)
PPP_PROT_REG_CB(on_get_current_process)
PPP_PROT_REG_CB(on_get_modules)
PPP_PROT_REG_CB(on_get_libraries)
PPP_PROT_REG_CB(on_free_osiproc)
PPP_PROT_REG_CB(on_free_osiprocs)
PPP_PROT_REG_CB(on_free_osimodules)
#ifdef OSI_PROC_EVENTS
PPP_PROT_REG_CB(on_process_start)
PPP_PROT_REG_CB(on_process_end)
#endif

PPP_CB_BOILERPLATE(on_get_processes)
PPP_CB_BOILERPLATE(on_get_current_process)
PPP_CB_BOILERPLATE(on_get_modules)
PPP_CB_BOILERPLATE(on_get_libraries)
PPP_CB_BOILERPLATE(on_free_osiproc)
PPP_CB_BOILERPLATE(on_free_osiprocs)
PPP_CB_BOILERPLATE(on_free_osimodules)
#ifdef OSI_PROC_EVENTS
PPP_CB_BOILERPLATE(on_process_start)
PPP_CB_BOILERPLATE(on_process_end)
#endif

// The copious use of pointers to pointers in this file is due to
// the fact that PPP doesn't support return values (since it assumes
// that you will be running multiple callbacks at one site)

OsiProcs *get_processes(CPUState *cpu) {
    OsiProcs *p = NULL;
    PPP_RUN_CB(on_get_processes, cpu, &p);
    return p;
}

OsiProc *get_current_process(CPUState *cpu) {
    OsiProc *p = NULL;
    PPP_RUN_CB(on_get_current_process, cpu, &p);
    return p;
}

OsiModules *get_modules(CPUState *cpu) {
    OsiModules *m = NULL;
    PPP_RUN_CB(on_get_modules, cpu, &m);
    return m;
}

OsiModules *get_libraries(CPUState *cpu, OsiProc *p) {
    OsiModules *m = NULL;
    PPP_RUN_CB(on_get_libraries, cpu, p, &m);
    return m;
}

void free_osiproc(OsiProc *p) {
    PPP_RUN_CB(on_free_osiproc, p);
}

void free_osiprocs(OsiProcs *ps) {
    PPP_RUN_CB(on_free_osiprocs, ps);
}

void free_osimodules(OsiModules *ms) {
    PPP_RUN_CB(on_free_osimodules, ms);
}


#ifdef OSI_PROC_EVENTS
int asid_changed(CPUState *cpu, target_ulong oldval, target_ulong newval) {
    uint32_t i;
    OsiProcs *ps, *in, *out;
    ps = in = out = NULL;

    /* some callback has to be registered for retrieving processes */
    assert(PPP_CHECK_CB(on_get_processes) != 0);

    /* update process state */
    ps = get_processes(cpu);
    procstate_update(ps, &in, &out);

    /* invoke callbacks for finished processes */
    if (out != NULL) {
        for (i=0; i<out->num; i++) {
            PPP_RUN_CB(on_process_end, cpu, &out->proc[i]);
        }
        free_osiprocs(out);
    }

    /* invoke callbacks for new processes */
    if (in != NULL) {
        for (i=0; i<in->num; i++) {
            PPP_RUN_CB(on_process_start, cpu, &in->proc[i]);
        }
        free_osiprocs(in);
    }

    return 0;
}
#endif

extern const char *qemu_file;

bool init_plugin(void *self) {
#ifdef OSI_PROC_EVENTS
    panda_cb pcb = { .asid_changed = asid_changed };
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
#endif
    // figure out what kind of os introspection is needed and grab it? 
    assert (!(panda_os_familyno == OS_UNKNOWN));
    if (panda_os_familyno == OS_LINUX) {
        // sadly, all of this is to find kernelinfo.conf file
        const gchar *progname = qemu_file;
        gchar *progname_path;
        gchar *progdir;

        // get absolute path to qemu program name and dir
        if (!g_path_is_absolute(progname)) {
            gchar *cwd = g_get_current_dir();
            progname_path = g_build_filename(cwd, progname, NULL);
            g_free(cwd);
            progdir = g_path_get_dirname(progname_path);
            g_free(progname_path);
        }
        else {
            progdir = g_path_get_dirname(progname);
        }

        // get path to kconffile and canonicalize
        gchar *kconffile = g_build_filename(progdir, "panda", "plugins", "osi_linux", "kernelinfo.conf", NULL);
        printf("Looking for kconffile in %s\n", kconffile);
        gchar *kconffile_canon = realpath(kconffile, NULL);
        if (kconffile_canon == NULL) {
            g_free(kconffile);
            kconffile = g_build_filename(progdir, "..",
                    "panda", "plugins",
                    "osi_linux", "kernelinfo.conf", NULL);
            printf("Looking for kconffile in %s\n", kconffile);
            kconffile_canon = realpath(kconffile, NULL);
        }
        g_free(progdir);
        assert(kconffile_canon != NULL);

        // convert stdlib buffer to glib buffer
        g_free(kconffile);
        kconffile = g_strdup(kconffile_canon);
        free(kconffile_canon);

        // get kconfgroup
        gchar *kconfgroup = g_strdup_printf("%s:%d", panda_os_variant, panda_os_bits);

        // add arguments to panda
        gchar *plugin_arg;
        plugin_arg = g_strdup_printf("kconf_file=%s", kconffile);
        panda_add_arg("osi_linux", plugin_arg);
        g_free(plugin_arg);
        plugin_arg = g_strdup_printf("kconf_group=%s", kconfgroup);
        panda_add_arg("osi_linux", plugin_arg);
        g_free(plugin_arg);

        // print info and finish
        g_printf("OSI grabbing Linux introspection backend.\n");
        g_printf("Linux OSI, using group %s from %s.\n", kconfgroup, kconffile);
        g_free(kconffile);
        g_free(kconfgroup);

        panda_require("osi_linux");
    }
    if (panda_os_familyno == OS_WINDOWS) {
        g_printf("OSI grabbing Windows introspection backend.\n");
        panda_require("wintrospection");
    }
    return true;
}

void uninit_plugin(void *self) { }
