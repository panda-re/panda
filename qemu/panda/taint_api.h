
#ifndef __TAINT_API_H_
#define __TAINT_API_H_

#include "taint_processor.h"


// api to taint plugin that needs to be exposed to other plugins


// turns on taint
extern "C" void taint_enable_taint(void);

// returns 1 if taint is on
extern "C" int taint_enabled(void);

// label this phys addr in memory with label l
extern "C" void taint_label_ram(uint64_t pa, uint32_t l);


// if phys addr pa is untainted, return 0.
// else returns label set cardinality 
extern "C" uint32_t taint_query_ram(uint64_t pa);

// if offset of reg is untainted, ...
extern "C" uint32_t taint_query_reg(int reg_num, int offset);

// delete taint from this phys addr
extern "C" void taint_delete_ram(uint64_t pa) ;

// iterate over labels associated with phys addr pa and apply fn app.
// stuff2 gets passed to app as 2nd arg. 
extern "C" void taint_labels_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2) ; 

// ditto but for this offset within this reg
extern "C" void taint_labels_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// returns number of tainted addrs in ram
extern "C" uint32_t taint_occ_ram();

#endif 
