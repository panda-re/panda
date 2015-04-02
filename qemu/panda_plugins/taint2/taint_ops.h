/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

#ifndef __TAINT_OPS_H_
#define __TAINT_OPS_H_

#include <cstdint>

//namespace llvm { class FastShad; }
class FastShad;

extern "C" {

// taint2_memlog
//
// This will replace the dynamic log, since we now need to track values for
// a much shorter period of time. Instead of full-fledged file logging, we're
// just going to use a ring buffer.

// Initialize this to 0.
#define TAINT2_MEMLOG_SIZE 2
typedef struct taint2_memlog {
    uint64_t ring[TAINT2_MEMLOG_SIZE];
    uint64_t idx;
} taint2_memlog;

uint64_t taint_memlog_pop(taint2_memlog *memlog);

void taint_memlog_push(taint2_memlog *memlog, uint64_t val);

// taint_pop_frame; taint_push_frame
//
// Functions for dealing with function frames. We'll just advance and retract
// the label array pointer to make a new frame.
void taint_reset_frame(FastShad *shad);
void taint_push_frame(FastShad *shad);
void taint_pop_frame(FastShad *shad);

// Bookkeeping.
void taint_breadcrumb(uint64_t *dest_ptr, uint64_t bb_slot);

// Call out to PPP callback.
void taint_branch(FastShad *shad, uint64_t src);

// Taint operations
//
// These are all the taint operations which we will inline into the LLVM code
// as it JITs.
void taint_copy(
        FastShad *shad_dest, uint64_t dest,
        FastShad *shad_src, uint64_t src,
        uint64_t size);

// Two compute models: parallel and mixed. Parallel for bitwise, mixed otherwise.
// Parallel compute: take labelset vectors [1,2,3] + [4,5,6] -> [14,25,36]
void taint_parallel_compute(
        FastShad *shad,
        uint64_t dest, uint64_t ignored,
        uint64_t src1, uint64_t src2, uint64_t src_size);

// Mixed compute: [1,2] + [3,4] -> [1234,1234]
// Note that dest_size and src_size can differ.
void taint_mix_compute(
        FastShad *shad,
        uint64_t dest, uint64_t dest_size,
        uint64_t src1, uint64_t src2, uint64_t src_size);

// Clear taint.
void taint_delete(FastShad *shad, uint64_t dest, uint64_t size);

// Copy a single value to multiple destinations. (i.e. memset)
void taint_set(
        FastShad *shad_dest, uint64_t dest, uint64_t dest_size,
        FastShad *shad_src, uint64_t src);

// Union all labels within here: [1,2,3] -> [123,123,123]
// A mixed compute becomes two mixes followed by a parallel.
void taint_mix(
        FastShad *shad,
        uint64_t dest, uint64_t dest_size,
        uint64_t src, uint64_t src_size);

// Tainted pointer load in tainted pointer mode.
// Mixes the ptr labels and parallels that with each src label.
void taint_pointer(
        FastShad *shad_dest, uint64_t dest,
        FastShad *shad_ptr, uint64_t ptr, uint64_t ptr_size,
        FastShad *shad_src, uint64_t src, uint64_t size);

// Only generate when signed and dest_size > src_size.
// Otherwise it should just be a copy.
void taint_sext(
        FastShad *shad,
        uint64_t dest, uint64_t dest_size,
        uint64_t src, uint64_t src_size);

// Takes a NULL-terminated list of (value, select) pairs.
void taint_select(
        FastShad *shad,
        uint64_t dest, uint64_t size, uint64_t selector,
        ...);

void taint_host_copy(
        uint64_t env_ptr, uint64_t addr,
        FastShad *llv, uint64_t llv_offset,
        FastShad *greg, FastShad *gspec,
        uint64_t size, uint64_t labels_per_reg, bool is_store);

void taint_host_memcpy(
        uint64_t env_ptr, uint64_t dest, uint64_t src,
        FastShad *greg, FastShad *gspec,
        uint64_t size, uint64_t labels_per_reg);

void taint_host_delete(
        uint64_t env_ptr, uint64_t dest_addr,
        FastShad *greg, FastShad *gspec,
        uint64_t size, uint64_t labels_per_reg);

} // extern "C"

#endif
