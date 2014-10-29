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

void taint_copy(uintptr_t shad_dest_ptr, uint64_t dest, uintptr_t shad_src_ptr, uint64_t src, uint64_t size) {
    FastShad *shad_dest = (FastShad *)shad_dest_ptr;
    FastShad *shad_src = (FastShad *)shad_src_ptr;
    fast_shad_copy(shad_dest, dest, shad_src, src, size);
}

void taint_parallel(uintptr_t shad_ptr, uint64_t dest, uint64_t src1, uint64_t src2, uint64_t size) {
    FastShad *shad = (FastShad *)shad_ptr;
    for (uint64_t i = 0; i < size; ++i) {
        LabelSet *ls = label_set_union(
                fast_shad_query(shad, src1 + i),
                fast_shad_query(shad, src2 + i));
        fast_shad_set(shad, dest, 1, ls);
    }
}

static inline LabelSet *mixed_labels(uintptr_t shad_ptr, uint64_t addr, uint64_t size) {
    LabelSet *ls = NULL;
    for (uint64_t i = 0; i < size; ++i) {
        ls = label_set_union(ls, fast_shad_query(shad, addr + i));
    }
    return ls;
}

void taint_mix(uintptr_t shad_ptr, uint64_t dest, uint64_t src1, uint64_t src2, uint64_t size) {
    FastShad *shad = (FastShad *)shad_ptr;
    LabelSet *ls = label_set_union(
            mixed_labels(shad, src1, size),
            mixed_labels(shad, src2, size));
    fast_shad_set(shad, dest, size, ls);
}

void taint_delete(uintptr_t shad_ptr, uint64_t dest, uint64_t size) {
    FastShad *shad = (FastShad *)shad_ptr;
    fast_shad_set(shad, dest, size, NULL);
}

void taint_sext(uintptr_t shad_ptr, uint64_t dest, uint64_t dest_size, uint64_t src, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr
    fast_shad_copy(shad, dest, shad, src, src_size);
    fast_shad_set(shad, dest + src_size, dest_size - src_size,
            fast_shad_query(shad, dest + src_size - 1));
}
