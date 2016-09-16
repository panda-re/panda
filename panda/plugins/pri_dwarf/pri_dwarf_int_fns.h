#ifndef __DWARFP_INT_FNS_H__
#define __DWARFP_INT_FNS_H__

// iterate through the live vars at the current state of execution
void dwarf_all_livevar_iter(CPUState *env, target_ulong pc, liveVarCB f);

// iterate through the function vars at the current state of execution
void dwarf_funct_livevar_iter(CPUState *env, target_ulong pc, liveVarCB f);

// iterate through the global vars at the current state of execution
void dwarf_global_livevar_iter(CPUState *env, target_ulong pc, liveVarCB f);

#endif
/* vim:set tabstop=4 softabstop=4 noexpandtab */
