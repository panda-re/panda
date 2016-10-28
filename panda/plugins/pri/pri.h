#ifndef PRI_H
#define PRI_H

typedef void (*on_get_pc_source_info_t)(CPUState *a, target_ulong pc, SrcInfo *info, int *rc);
typedef void (*on_get_vma_symbol_t)(CPUState *env, target_ulong pc, target_ulong vma, char **symbol_name);
typedef void (*on_all_livevar_iter_t)(CPUState *a, target_ulong pc, liveVarCB f, void *args);
typedef void (*on_global_livevar_iter_t)(CPUState *a, target_ulong pc, liveVarCB f, void *args);
typedef void (*on_funct_livevar_iter_t)(CPUState *a, target_ulong pc, liveVarCB f, void *args);


typedef void (*on_before_line_change_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);
typedef void (*on_after_line_change_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);
typedef void (*on_fn_start_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name);
typedef void (*on_fn_return_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name);

#endif 
