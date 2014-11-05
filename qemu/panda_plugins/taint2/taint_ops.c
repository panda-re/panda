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

#include "fast_shad.h"
#include "labelset.h"
#include "taint_ops.h"

// Memlog functions.

uint64_t taint2_memlog_pop(uint64_t memlog_ptr) {
    taint2_memlog memlog = (taint2_memlog *)memlog_ptr;
    uint64_t result = memlog->ring[memlog->idx];
    memlog->idx = (memlog->idx + TAINT2_MEMLOG_SIZE - 1) % TAINT2_MEMLOG_SIZE;;
    return result;
}

void taint2_memlog_push(uint64_t memlog_ptr, uint64_t val) {
    taint2_memlog memlog = (taint2_memlog *)memlog_ptr;
    memlog->idx = (memlog->idx + 1) % TAINT2_MEMLOG_SIZE;;
    memlog->ring[memlog->idx] = val;
}

// Bookkeeping.
void taint_breadcrumb(uint64_t dest_ptr, uint64_t bb_slot) {
    *(uint64_t *)dest_ptr = bb_slot;
}

// Stack frame operations

void taint_push_frame(uint64_t shad_ptr) {
    fast_shad_push_frame((FastShad *)shad_ptr);
}
void taint_pop_frame(uint64_t shad_ptr) {
    fast_shad_pop_frame((FastShad *)shad_ptr);
}

// Taint operations
void taint_copy(
        uint64_t shad_dest_ptr, uint64_t dest,
        uint64_t shad_src_ptr, uint64_t src,
        uint64_t size) {
    FastShad *shad_dest = (FastShad *)shad_dest_ptr;
    FastShad *shad_src = (FastShad *)shad_src_ptr;
    fast_shad_copy(shad_dest, dest, shad_src, src, size);
}

void taint_move(
        uint64_t shad_dest_ptr, uint64_t dest,
        uint64_t shad_src_ptr, uint64_t src,
        uint64_t size) {
    FastShad *shad_dest = (FastShad *)shad_dest_ptr;
    FastShad *shad_src = (FastShad *)shad_src_ptr;
    fast_shad_move(shad_dest, dest, shad_src, src, size);
}

void taint_parallel_compute(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t ignored,
        uint64_t src1, uint64_t src2, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr;
    for (uint64_t i = 0; i < size; ++i) {
        LabelSet *ls = label_set_union(
                fast_shad_query(shad, src1 + i),
                fast_shad_query(shad, src2 + i));
        fast_shad_set(shad, dest, 1, ls);
    }
}

static inline LabelSet *mixed_labels(FastShad *shad, uint64_t addr, uint64_t size) {
    LabelSet *ls = NULL;
    for (uint64_t i = 0; i < size; ++i) {
        ls = label_set_union(ls, fast_shad_query(shad, addr + i));
    }
    return ls;
}

void taint_mix_compute(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t dest_size,
        uint64_t src1, uint64_t src2, uint64_t src_size)
    FastShad *shad = (FastShad *)shad_ptr;
    LabelSet *ls = label_set_union(
            mixed_labels(shad, src1, src_size),
            mixed_labels(shad, src2, src_size));
    fast_shad_set(shad, dest, dest_size, ls);
}

void taint_delete(uint64_t shad_ptr, uint64_t dest, uint64_t size) {
    FastShad *shad = (FastShad *)shad_ptr;
    fast_shad_set(shad, dest, size, NULL);
}

void taint_set(
        uint64_t shad_dest_ptr, uint64_t dest, uint64_t dest_size,
        uint64_t shad_src_ptr, uint64_t src) {
    FastShad *shad_dest = (FastShad *)shad_dest_ptr;
    FastShad *shad_src = (FastShad *)shad_src_ptr;
    fast_shad_set(shad_dest, dest, dest_size, fast_shad_query(shad_src, src));
}

void taint_mix(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t dest_size,
        uint64_t src, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr;
    fast_shad_set(shad, dest, dest_size, mixed_labels(shad, src, src_size));
}

void taint_sext(uint64_t shad_ptr, uint64_t dest, uint64_t dest_size, uint64_t src, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr;
    fast_shad_copy(shad, dest, shad, src, src_size);
    fast_shad_set(shad, dest + src_size, dest_size - src_size,
            fast_shad_query(shad, dest + src_size - 1));
}

// Takes a NULL-terminated list of (shad_src, value, select) triples.
void taint_select(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t size, uint64_t selector,
        ...) {
    FastShad *shad_dest = (FastShad *)shad_ptr;
    va_list argp;
    uint64_t src, srcsel;
    FastShad *shad_src;

    va_start(argp, selector);
    shad_src = (FastShad *)va_arg(argp, (FastShad *));
    while (shad_src_ptr != 0) {
        src = va_arg(argp, uint64_t);
        srcsel = va_Arg(argp, uint64_t);

        if (srcsel == selector) { // bingo!
            fast_shad_copy(shad_dest, dest, shad_src, src, size);
            return;
        }

        shad_src = (FastShad *)va_arg(argp, (FastShad *));
    } 

    assert(false && "Couldn't find selected argument!!");
}
