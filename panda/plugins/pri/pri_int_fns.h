#ifndef __PRI_INT_FNS_H__
#define __PRI_INT_FNS_H__

// Public Interface

// get source info for a pc at current execution return -1 if in external libraries that do not have symbol information
int pri_get_pc_source_info (CPUState *env, target_ulong pc, SrcInfo *info);

// get dwarf symbol info for a Virtual Memory Address while execution is at pc. Return `NULL` if external libraries that do not have symbol information
char *pri_get_vma_symbol (CPUState *env, target_ulong pc, target_ulong vma);

// iterate through the live vars at the current state of execution
void pri_all_livevar_iter (CPUState *env, target_ulong pc, liveVarCB f, void *args);

// iterate through the function vars at the current state of execution
void pri_funct_livevar_iter (CPUState *env, target_ulong pc, liveVarCB f, void *args); 

// iterate through the global vars at the current state of execution
void pri_global_livevar_iter (CPUState *env, target_ulong pc, liveVarCB f, void *args);


// Intended for use only by pri Providers
void pri_runcb_on_before_line_change(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);
void pri_runcb_on_after_line_change(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);
void pri_runcb_on_fn_start(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name);
void pri_runcb_on_fn_return(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name);
#endif
