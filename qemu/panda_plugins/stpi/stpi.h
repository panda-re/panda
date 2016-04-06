#ifndef TEST_STPI_H
#define TEST_STPI_H

typedef void (*on_all_livevar_iter_t)(CPUState *a, target_ulong pc, liveVarCB f);
typedef void (*on_global_livevar_iter_t)(CPUState *a, target_ulong pc, liveVarCB f);
typedef void (*on_funct_livevar_iter_t)(CPUState *a, target_ulong pc, liveVarCB f);


typedef void (*on_line_change_t)(CPUState *env, target_ulong pc, const char *file_name, const char *funct_name, unsigned long long lno);
#endif 
