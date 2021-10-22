#ifndef PRI_H
#define PRI_H

PPP_CB_TYPEDEF(void, on_get_pc_source_info, CPUState *a, target_ulong pc, SrcInfo *info, int *rc);
PPP_CB_TYPEDEF(void, on_get_vma_symbol, CPUState *env, target_ulong pc, target_ulong vma, char **symbol_name);
PPP_CB_TYPEDEF(void, on_all_livevar_iter, CPUState *a, target_ulong pc, liveVarCB f, void *args);
PPP_CB_TYPEDEF(void, on_global_livevar_iter, CPUState *a, target_ulong pc, liveVarCB f, void *args);
PPP_CB_TYPEDEF(void, on_funct_livevar_iter, CPUState *a, target_ulong pc, liveVarCB f, void *args);


PPP_CB_TYPEDEF(void, on_before_line_change, CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);
PPP_CB_TYPEDEF(void, on_after_line_change, CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);
PPP_CB_TYPEDEF(void, on_fn_start, CPUState *env, target_ulong pc, const char *file_name, const char *funct_name);
PPP_CB_TYPEDEF(void, on_fn_return, CPUState *env, target_ulong pc, const char *file_name, const char *funct_name);

#endif 
