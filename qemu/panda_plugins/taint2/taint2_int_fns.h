
#ifndef __TAINT_INT_FNS_H__
#define __TAINT_INT_FNS_H__


#include <stdint.h>
#include <stdbool.h>
#include "../../panda/panda_addr.h"

typedef void *LabelSetP;


// turns on taint
void taint2_enable_taint(void);

// returns 1 if taint is on
int taint2_enabled(void);

// label this phys addr in memory with label l
void taint2_label_ram(uint64_t pa, uint32_t l);

// query fns return 0 if untainted, else cardinality of taint set
uint32_t taint2_query(Addr a);
uint32_t taint2_query_ram(uint64_t pa);
uint32_t taint2_query_reg(int reg_num, int offset);
uint32_t taint2_query_llvm(int reg_num, int offset);

// returns taint compute number associated with addr
uint32_t taint2_query_tcn(Addr a);
uint32_t taint2_query_tcn_ram(uint64_t pa);
uint32_t taint2_query_tcn_reg(int reg_num, int offset);
uint32_t taint2_query_tcn_llvm(int reg_num, int offset);

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


// returns set of so-far applied labels as a sorted array
// NB: This allocates memory. Caller frees.
uint32_t *taint2_labels_applied(void);

// just tells how big that labels_applied set will be
uint32_t taint2_num_labels_applied(void);

// Track whether taint state actually changed during a BB
void taint2_track_taint_state(void);


// queries taint on this virtual addr and, if any taint there,
// writes an entry to pandalog with lots of stuff like
// label set, taint compute #, call stack
uint8_t taint2_query_pandalog (Addr a) ;


#endif                                                                                   
