#ifndef PRI_TYPES_H
#define PRI_TYPES_H


typedef struct { const char *filename; const char *funct_name; unsigned long line_number; } SrcInfo;
typedef enum { LocReg, LocMem, LocConst, LocErr } LocType;
typedef int (*liveVarPred)(void *var_ty, const char *var_nm, LocType loc_t, target_ulong loc, void *args);
typedef void (*liveVarCB)(void *var_ty, const char *var_nm, LocType loc_t, target_ulong loc, void *args);

#endif
