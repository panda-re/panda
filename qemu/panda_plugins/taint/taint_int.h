
#ifndef __TAINT_INT_H_
#define __TAINT_INT_H_

#include "taint_processor.h"

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

// returns number of tainted addrs in ram
uint32_t taint_occ_ram(void);

// returns the max ls type (taint compute #) observed so far
uint32_t taint_max_obs_ls_type(void) ;

// clears the flag indicating tainted computation happened
void taint_clear_tainted_computation_happened(void);

// reads the flag indicating tainted computation happened
int taint_tainted_computation_happened(void);

// clears the flag indicating taint state has changed
void taint_clear_taint_state_changed(void);

// returns the flag
int taint_taint_state_changed(void);

// clears the flag indicating taint state has been read
void taint_clear_taint_state_read(void);

// returns the flag
int taint_taint_state_read(void);

   
#endif                                                                                   
