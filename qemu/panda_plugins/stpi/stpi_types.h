#ifndef SPI_TYPES_H
#define SPI_TYPES_H


typedef enum { LocReg, LocMem, LocConst, LocErr } LocType;
typedef void (*liveVarCB)(const char *var_ty, const char *var_nm, LocType loc_t, target_ulong loc);

#endif
