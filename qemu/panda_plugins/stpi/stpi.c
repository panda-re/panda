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

#include "stpi_types.h"
#include "stpi_int_fns.h"
#include "../osi/osi_types.h"
#include "stpi.h"
// callbacks that symbol table provider must provide functionality for
PPP_PROT_REG_CB(on_all_livevar_iter)
PPP_CB_BOILERPLATE(on_all_livevar_iter)
PPP_PROT_REG_CB(on_global_livevar_iter)
PPP_CB_BOILERPLATE(on_global_livevar_iter)
PPP_PROT_REG_CB(on_funct_livevar_iter)
PPP_CB_BOILERPLATE(on_funct_livevar_iter)
// callbacks provided to client
PPP_PROT_REG_CB(on_line_change)
PPP_CB_BOILERPLATE(on_line_change)
PPP_PROT_REG_CB(on_fn_start)
PPP_CB_BOILERPLATE(on_fn_start)

bool init_plugin(void *);
void uninit_plugin(void *);

// callback provided to symbol table provider
void stpi_all_livevar_iter (CPUState *env, target_ulong pc, liveVarCB f) {
    PPP_RUN_CB(on_all_livevar_iter, env, pc, f);
}
void stpi_global_livevar_iter (CPUState *env, target_ulong pc, liveVarCB f) {
    PPP_RUN_CB(on_global_livevar_iter, env, pc, f);
}
void stpi_funct_livevar_iter (CPUState *env, target_ulong pc, liveVarCB f) {
    PPP_RUN_CB(on_funct_livevar_iter, env, pc, f);
}

// callbacks provided to client
void stpi_runcb_on_line_change(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno){
    PPP_RUN_CB(on_line_change, env, pc, file_name, funct_name, lno);
}
void stpi_runcb_on_fn_start(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno){
    PPP_RUN_CB(on_fn_start, env, pc, file_name, funct_name, lno);
}

bool init_plugin(void *self) {
    return true;
}

void uninit_plugin(void *self) { }
