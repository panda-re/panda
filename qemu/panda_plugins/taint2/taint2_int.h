
#ifndef __TAINT_INT_H_
#define __TAINT_INT_H_

// turns on taint
void taint_enable_taint(void);

// returns 1 if taint is on
int taint_enabled(void);

// label this phys addr in memory with label l
void taint_label_ram(uint64_t pa, uint32_t l);

// if phys addr pa is untainted, return 0.
// else returns label set cardinality 
uint32_t taint_query_ram(uint64_t pa);

// if offset of reg is untainted, ...
uint32_t taint_query_reg(int reg_num, int offset);

// delete taint from this phys addr
void taint_delete_ram(uint64_t pa) ;

#endif                                                                                   
