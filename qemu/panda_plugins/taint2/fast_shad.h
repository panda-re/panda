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

#ifndef __FAST_SHAD_H
#define __FAST_SHAD_H

#include <stdint.h>

#include "defines.h"

void *memset(void *dest, int val, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);

typedef struct LabelSet LabelSet;

typedef struct FastShad {
    LabelSet **labels;
    uint64_t bytes;
} FastShad;

FastShad *fast_shad_new(uint64_t bytes);
void fast_shad_free(FastShad *fast_shad);

static inline void fast_shad_set(FastShad *fast_shad, uint64_t addr, LabelSet *ls);
static inline void fast_shad_move(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size);
static inline void fast_shad_copy(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size);
static inline void fast_shad_remove(FastShad *fast_shad, uint64_t addr, uint64_t size);
static inline LabelSet *fast_shad_query(FastShad *fast_shad, uint64_t addr);
static inline void fast_shad_push_frame(FastShad *fast_shad);
static inline void fast_shad_pop_frame(FastShad *fast_shad);

static inline LabelSet **get_ls_p(FastShad *fast_shad, uint64_t guest_addr) {
#ifndef FAST_SHAD_OR
    return &fast_shad->labels[guest_addr];
#else
    uint64_t base = (uint64_t)fast_shad->labels;
    uint64_t offset = guest_addr * sizeof(LabelSet *)
    // base is guaranteed to be a aligned to a large power of 2
    // so we don't need to add. multiply should optimize to a shift.
    return (LabelSet **)(base | offset);
#endif
}

// Taint an address with a labelset.
static inline void fast_shad_set(FastShad *fast_shad, uint64_t addr, LabelSet *ls) {
    *get_ls_p(fast_shad, addr) = ls;
}

static inline void fast_shad_copy(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size) {
    memcpy(get_ls_p(fast_shad_dest, dest), get_ls_p(fast_shad_src, src), size);
}

static inline void fast_shad_move(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size) {
    memmove(get_ls_p(fast_shad_dest, dest), get_ls_p(fast_shad_src, src), size);
}

// Remove taint.
static inline void fast_shad_remove(FastShad *fast_shad, uint64_t addr, uint64_t size) {
    memset(get_ls_p(fast_shad, addr), 0, size);
}

// Query. NULL if untainted.
static inline LabelSet *fast_shad_query(FastShad *fast_shad, uint64_t addr) {
    return *get_ls_p(fast_shad, addr);
} 

static inline void fast_shad_push_frame(FastShad *fast_shad) {
    fast_shad->labels += MAXREGSIZE * MAXFRAMESIZE;
}

static inline void fast_shad_pop_frame(FastShad *fast_shad) {
    fast_shad->labels -= MAXREGSIZE * MAXFRAMESIZE;
}

#endif
