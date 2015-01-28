
#ifndef __TAINT_INT_FNS_H__
#define __TAINT_INT_FNS_H__


#include <stdint.h>

typedef struct LabelSet *LabelSetP;


// turns on taint
void taint2_enable_taint(void);

// returns 1 if taint is on
int taint2_enabled(void);

// label this phys addr in memory with label l
void taint2_label_ram(uint64_t pa, uint32_t l);

// if phys addr pa is untainted, return 0.
// else returns label set cardinality 
uint32_t taint2_query_ram(uint64_t pa);

// if offset of reg is untainted, ...
uint32_t taint2_query_reg(int reg_num, int offset);

// delete taint from this phys addr
void taint2_delete_ram(uint64_t pa) ;

// spit labelset.
void taint2_labelset_spit(LabelSetP ls) ; 

// apply this fn to each of the labels associated with this pa
// fn should return 0 to continue iteration
void taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// ditto, but a machine register
// you should be able to use R_EAX, etc as reg_num
// offset is byte offset withing that reg.
void taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// ditto, but for llvm regs.  dunno where you are getting that number
void taint2_labelset_llvm_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// ditto, but someone handed you the ls, e.g. a callback like tainted branch
void taint2_labelset_iter(LabelSetP ls,  int (*app)(uint32_t el, void *stuff1), void *stuff2) ;


#endif                                                                                   
