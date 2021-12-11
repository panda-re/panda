#ifndef __TAINT_API_H_
#define __TAINT_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif

#include "branch_meta.h"

#ifndef PYPANDA
#include "taint2.h"
#endif

#include "z3++.h"

// typedef struct SymbolicBranchMeta {
//     target_ulong pc;

//     SymbolicBranchMeta(target_ulong prog_cnt): pc(prog_cnt) {};
// } SymbolicBranchMeta;

extern z3::context context;

extern "C" bool symexEnabled;

extern "C" void taint2_enable_sym(void);

extern "C" void taint2_sym_label_addr(Addr a, int offset, uint32_t l);

extern "C" void *taint2_sym_query(Addr a);

extern "C" void taint2_sym_query_ram(uint64_t RamOffset, uint32_t s, uint32_t *n, char** strptr);

extern "C" void taint2_sym_query_reg(uint32_t reg_num, uint32_t *n, char** strptr);

extern "C" void taint2_sym_branch_meta(uint32_t *n, SymbolicBranchMeta** metas);

extern "C" void taint2_sym_path_constraints(uint32_t *n, char** strptr);

extern "C" void taint2_sym_label_ram(uint64_t RamOffset, uint32_t l);

extern "C" void taint2_sym_label_reg(int reg_num, int offset, uint32_t l);

z3::expr *taint2_sym_query_expr(Addr a);

// register branch path constraint
void reg_branch_pc(z3::expr pc, bool concrete);
#endif
