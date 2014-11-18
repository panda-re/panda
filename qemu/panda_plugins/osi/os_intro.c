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

#include "config.h"
#include "qemu-common.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

#include "osi_types.h"
#include "osi_int.h"
#include "os_intro.h"

bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_get_processes)
PPP_PROT_REG_CB(on_get_current_process)
PPP_PROT_REG_CB(on_get_modules)
PPP_PROT_REG_CB(on_get_libraries)
PPP_PROT_REG_CB(on_free_osiproc)
PPP_PROT_REG_CB(on_free_osiprocs)
PPP_PROT_REG_CB(on_free_osimodules)

PPP_CB_BOILERPLATE(on_get_processes)
PPP_CB_BOILERPLATE(on_get_current_process)
PPP_CB_BOILERPLATE(on_get_modules)
PPP_CB_BOILERPLATE(on_get_libraries)
PPP_CB_BOILERPLATE(on_free_osiproc)
PPP_CB_BOILERPLATE(on_free_osiprocs)
PPP_CB_BOILERPLATE(on_free_osimodules)

// The copious use of pointers to pointers in this file is due to
// the fact that PPP doesn't support return values (since it assumes
// that you will be running multiple callbacks at one site)

OsiProcs *get_processes(CPUState *env) {
    OsiProcs *p = NULL;
    PPP_RUN_CB(on_get_processes, env, &p);
    return p;
}

OsiProc *get_current_process(CPUState *env) {
    OsiProc *p = NULL;
    PPP_RUN_CB(on_get_current_process, env, &p);
    return p;
}

OsiModules *get_modules(CPUState *env) {
    OsiModules *m = NULL;
    PPP_RUN_CB(on_get_modules, env, &m);
    return m;
}

OsiModules *get_libraries(CPUState *env, OsiProc *p) {
    OsiModules *m = NULL;
    PPP_RUN_CB(on_get_libraries, env, p, &m);
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

bool init_plugin(void *self) {
    return true;
}

void uninit_plugin(void *self) { }
