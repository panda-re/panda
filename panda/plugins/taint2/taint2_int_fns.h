#ifndef __TAINT_INT_FNS_H__
#define __TAINT_INT_FNS_H__

#include <stdint.h>
#include <stdbool.h>


// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

#include "addr.h"
#include "query_res.h"

// turns on taint
void taint2_enable_taint(void);

// turns on tainted pointer
void taint2_enable_tainted_pointer(void);

// returns 1 if taint is on
int taint2_enabled(void);

void taint2_label_addr(Addr a, int offset, uint32_t l);

// label this phys addr in memory with label l, and only label l. any previous
// labels applied to this address are removed.
void taint2_label_ram(uint64_t pa, uint32_t l);

// label this reg with label l, and only label l. any previous labels applied 
// to this address are removed.
void taint2_label_reg(int reg_num, int offset, uint32_t l);

// label this io addr with label l, and only label l. any previous
// labels applied to this address are removed.
void taint2_label_io(uint64_t ia, uint32_t l);

// add label l to this phys addr in memory. any previous labels applied to this
// address are not removed.
void taint2_label_ram_additive(uint64_t pa, uint32_t l);

// add label l to this register. any previous labels applied to this register
// are not removed.
void taint2_label_reg_additive(int reg_num, int offset, uint32_t l);

// add label l to this io addr. any previous labels applied to this
// address are not removed.
void taint2_label_io_additive(uint64_t ia, uint32_t l);

// query fns return 0 if untainted, else cardinality of taint set
uint32_t taint2_query(Addr a);
uint32_t taint2_query_ram(uint64_t pa);
uint32_t taint2_query_reg(int reg_num, int offset);
uint32_t taint2_query_io(uint64_t ia);
uint32_t taint2_query_laddr(uint64_t ia, uint64_t offset);

// query with automatic allocation of the required memory
uint32_t taint2_query_set_a(Addr a, uint32_t **out, uint32_t *outsz);

// query set fns writes taint set contents to the specified array. the size of
// the array must be >= the cardianlity of the taint set.
void taint2_query_set(Addr a, uint32_t *out);
void taint2_query_set_ram(uint64_t pa, uint32_t *out);
void taint2_query_set_reg(int reg_num, int offset, uint32_t *out);
void taint2_query_set_io(uint64_t ia, uint32_t *out);

// returns taint compute number associated with addr
uint32_t taint2_query_tcn(Addr a);
uint32_t taint2_query_tcn_ram(uint64_t pa);
uint32_t taint2_query_tcn_reg(int reg_num, int offset);
uint32_t taint2_query_tcn_io(uint64_t ia);

// Returns a mask indicating which bits are attacker-controlled (derived
// reversibly from input).
uint64_t taint2_query_cb_mask(Addr a, uint8_t size);

// delete taint from this phys addr
void taint2_delete_ram(uint64_t pa);

// delete taint from this register
void taint2_delete_reg(int reg_num, int offset);

// delete taint from this io addr
void taint2_delete_io(uint64_t ia);

// addr is an opaque.  it should be &a if a is known to be an Addr
void taint2_labelset_addr_iter(Addr addr, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// apply this fn to each of the labels associated with this pa
// fn should return 0 to continue iteration
void taint2_labelset_ram_iter(uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// ditto, but a machine register
// you should be able to use R_EAX, etc as reg_num
// offset is byte offset withing that reg.
void taint2_labelset_reg_iter(int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// apply this fn to each of the labels associated with this io address
// fn should return 0 to continue iteration
void taint2_labelset_io_iter(uint64_t ia, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// just tells how big that labels_applied set will be
uint32_t taint2_num_labels_applied(void);

// Track whether taint state actually changed during a BB
void taint2_track_taint_state(void);

typedef uint32_t TaintLabel;

// Initializes the labelset label iterator in the query result
// meaning rewinding it to first label in set
void taint2_query_results_iter(QueryResult *qr);

// Returns current label in set and moves on to next. Sets *bool to
// true if there are no more labels and false otherwise
uint32_t taint2_query_result_next(QueryResult *qr, bool *done);

// Places taint query results for this register / offset byte in
// returned qr.  qr's label set iterator is pre initialized, so there
// is no need to call taint2_query_results_iter unless you want to
// iterate through labels more than once).
void taint2_query_reg_full(uint32_t reg_num, uint32_t offset, QueryResult *qr);


// Places taint query results for this physical address in
// returned qr.  qr's label set iterator is pre initialized, so there
// is no need to call taint2_query_results_iter unless you want to
// iterate through labels more than once).
void taint2_query_ram_full(uint64_t pa, QueryResult *qr);

// Places taint query results for this laaddress in
// returned qr.  qr's label set iterator is pre initialized, so there
// is no need to call taint2_query_results_iter unless you want to
// iterate through labels more than once).
void taint2_query_laddr_full(uint64_t la, uint64_t offset, QueryResult *qr);


// END_PYPANDA_NEEDS_THIS -- do not delete this comment!


// queries taint on this virtual addr and, if any taint there, writes
// an entry to pandalog with lots of stuff like label set, taint
// compute #, call stack offset is needed since this is likely a query
// in the middle of an extent (of 4, 8, or more bytes)
Panda__TaintQuery *taint2_query_pandalog (Addr addr, uint32_t offset);

// used to free memory associated with that struct
void pandalog_taint_query_free(Panda__TaintQuery *tq);



#endif

