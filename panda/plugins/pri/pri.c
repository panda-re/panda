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

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "pri_types.h"
#include "pri_int_fns.h"
#include "osi/osi_types.h"
#include "pri.h"
// callbacks that symbol table provider must provide functionality for
PPP_PROT_REG_CB(on_get_pc_source_info)
PPP_CB_BOILERPLATE(on_get_pc_source_info)
PPP_PROT_REG_CB(on_get_vma_symbol)
PPP_CB_BOILERPLATE(on_get_vma_symbol)
PPP_PROT_REG_CB(on_all_livevar_iter)
PPP_CB_BOILERPLATE(on_all_livevar_iter)
PPP_PROT_REG_CB(on_global_livevar_iter)
PPP_CB_BOILERPLATE(on_global_livevar_iter)
PPP_PROT_REG_CB(on_funct_livevar_iter)
PPP_CB_BOILERPLATE(on_funct_livevar_iter)
// callbacks provided to client
PPP_PROT_REG_CB(on_before_line_change)
PPP_CB_BOILERPLATE(on_before_line_change)
PPP_PROT_REG_CB(on_after_line_change)
PPP_CB_BOILERPLATE(on_after_line_change)
PPP_PROT_REG_CB(on_fn_start)
PPP_CB_BOILERPLATE(on_fn_start)
PPP_PROT_REG_CB(on_fn_return)
PPP_CB_BOILERPLATE(on_fn_return)

bool init_plugin(void *);
void uninit_plugin(void *);

// callback provided to symbol table provider
int pri_get_pc_source_info (CPUState *cpu, target_ulong pc, SrcInfo *info) {
    int rc;
    PPP_RUN_CB(on_get_pc_source_info, cpu, pc, info, &rc);
    return rc;
}

// callback provided to symbol table provider
char* pri_get_vma_symbol (CPUState *cpu, target_ulong pc, target_ulong vma) {
    char *symbol_name = NULL;
    PPP_RUN_CB(on_get_vma_symbol, cpu, pc, vma, &symbol_name);
    return symbol_name;
}

void pri_all_livevar_iter (CPUState *cpu, target_ulong pc, liveVarCB f, void *args) {
    PPP_RUN_CB(on_all_livevar_iter, cpu, pc, f, args);
}
void pri_global_livevar_iter (CPUState *cpu, target_ulong pc, liveVarCB f, void *args) {
    PPP_RUN_CB(on_global_livevar_iter, cpu, pc, f, args);
}
void pri_funct_livevar_iter (CPUState *cpu, target_ulong pc, liveVarCB f, void *args) {
    PPP_RUN_CB(on_funct_livevar_iter, cpu, pc, f, args);
}

// callbacks provided to client
void pri_runcb_on_before_line_change(CPUState *cpu, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno){
    PPP_RUN_CB(on_before_line_change, cpu, pc, file_name, funct_name, lno);
}
void pri_runcb_on_after_line_change(CPUState *cpu, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno){
    PPP_RUN_CB(on_after_line_change, cpu, pc, file_name, funct_name, lno);
}
void pri_runcb_on_fn_start(CPUState *cpu, target_ulong pc, const char *file_name, const char *funct_name){
    PPP_RUN_CB(on_fn_start, cpu, pc, file_name, funct_name);
}
void pri_runcb_on_fn_return(CPUState *cpu, target_ulong pc, const char *file_name, const char *funct_name){
    PPP_RUN_CB(on_fn_return, cpu, pc, file_name, funct_name);
}


bool init_plugin(void *self) {
    return true;
}

void uninit_plugin(void *self) { }
