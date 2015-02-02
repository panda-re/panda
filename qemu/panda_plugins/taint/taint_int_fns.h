
#ifndef __TAINT_INT_FNS_H__
#define __TAINT_INT_FNS_H__

#include <stdint.h>

// turns on taint
void taint_enable_taint(void);

// returns 1 if taint is on
int taint_enabled(void);

// label this phys addr in memory with label l
void taint_label_ram(uint64_t pa, uint32_t l);


// if phys addr pa is untainted, return 0.
// else returns label set cardinality 
uint32_t taint_query_ram(uint64_t pa);

// Return one label; ~0 if not labeled.
uint32_t taint_pick_label(uint64_t pa);

// if offset of reg is untainted, ...
uint32_t taint_query_reg(int reg_num, int offset);

// if offset of llvm reg is untainted, ...
uint32_t taint_query_llvm(int reg_num, int offset);

// Print the labels on a register
void taint_spit_reg(int reg_num, int offset);

// Print the labels on an llvm register
void taint_spit_llvm(int reg_num, int offset);

// delete taint from this phys addr
void taint_delete_ram(uint64_t pa) ;

// returns number of tainted addrs in ram
uint32_t taint_occ_ram(void);

// returns the max ls type (taint compute #) observed so far
uint32_t taint_max_obs_ls_type(void) ;

// returns the ls type (taint compute #) for the given llvm register
uint32_t taint_get_ls_type_llvm(int reg_num, int offset);

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

// Clear all taint from the shadow memory (by reinstantiating it)
void taint_clear_shadow_memory(void);



// apply this fn to each of the labels associated with this pa
// fn should return 0 to continue iteration
void taint_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// ditto, but a machine register
// you should be able to use R_EAX, etc as reg_num
// offset is byte offset withing that reg.
void taint_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// ditto, but for llvm regs.  dunno where you are getting that number
void taint_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// ditto, but someone handed you the ls, e.g. a callback like tainted branch
void taint_labelset_iter(LabelSetP ls,  int (*app)(uint32_t el, void *stuff1), void *stuff2) ;



#endif                                                                                   
