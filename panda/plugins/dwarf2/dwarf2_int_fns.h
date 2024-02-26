#ifndef __DWARF2_INT_FNS_H__
#define __DWARF2_INT_FNS_H__

// iterate through type tree and perform a cb (designed to be related to taint)
// on each address computed
void dwarf2_type_iter (CPUState *env, target_ulong base_addr, LocType loc_t, DwarfVarType *var_ty, dwarfTypeCB cb, int recursion_level);
// convert a variable to its name. Right now we can't abstract
// this to PRI, so we to leave it to the pri providers
// to create this type of function for a custom var data type
const char *dwarf2_type_to_string(DwarfVarType *var_ty);

target_ulong dwarf2_get_cur_fp(CPUState *env, target_ulong pc);

#endif
/* vim:set tabstop=4 softabstop=4 noexpandtab */
