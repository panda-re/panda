#ifndef SPI_TYPES_H
#define SPI_TYPES_H


typedef struct { const char *filename; const char *funct_name; unsigned long line_number; } PC_Info;
typedef enum { LocReg, LocMem, LocConst, LocErr } LocType;
typedef void (*liveVarCB)(const char *var_ty, const char *var_nm, LocType loc_t, target_ulong loc);

#endif
