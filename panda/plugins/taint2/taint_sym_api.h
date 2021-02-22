#ifndef __TAINT_API_H_
#define __TAINT_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif

#ifndef PYPANDA
#include "taint2.h"
#endif

#include "z3++.h"

extern z3::context context;
extern "C" {
void taint2_sym_label_addr(Addr a, int offset, uint32_t l);

void *taint2_sym_query(Addr a);

void taint2_sym_label_ram(uint64_t RamOffset, uint32_t l);
}

z3::expr *taint2_sym_query_expr(Addr a);


// register branch path constraint
void reg_branch_pc(z3::expr pc, bool concrete);
#endif
