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
    uint64_t size; // Number of labelsets contained.
} FastShad;

FastShad *fast_shad_new(uint64_t size);
void fast_shad_free(FastShad *fast_shad);

static inline void fast_shad_set(FastShad *fast_shad, uint64_t addr, LabelSet *ls);
static inline void fast_shad_move(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size);
static inline void fast_shad_copy(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size);
static inline void fast_shad_remove(FastShad *fast_shad, uint64_t addr, uint64_t size);
static inline LabelSet *fast_shad_query(FastShad *fast_shad, uint64_t addr);
static inline void fast_shad_push_frame(FastShad *fast_shad);
static inline void fast_shad_pop_frame(FastShad *fast_shad);

static inline LabelSet **get_ls_p(FastShad *fast_shad, uint64_t guest_addr) {
#ifdef TAINTDEBUG
    assert(guest_addr < fast_shad->size);
#endif
    return &fast_shad->labels[guest_addr];
}

// Taint an address with a labelset.
static inline void fast_shad_set(FastShad *fast_shad, uint64_t addr, LabelSet *ls) {
    *get_ls_p(fast_shad, addr) = ls;
}

static inline void fast_shad_copy(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size) {
#ifdef TAINTDEBUG
    assert(dest + size <= fast_shad_dest->size);
    assert(src + size <= fast_shad_src->size);
#endif
    memcpy(get_ls_p(fast_shad_dest, dest), get_ls_p(fast_shad_src, src), size);
}

static inline void fast_shad_move(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size) {
#ifdef TAINTDEBUG
    assert(dest + size <= fast_shad_dest->size);
    assert(src + size <= fast_shad_src->size);
#endif
    memmove(get_ls_p(fast_shad_dest, dest), get_ls_p(fast_shad_src, src), size);
}

// Remove taint.
static inline void fast_shad_remove(FastShad *fast_shad, uint64_t addr, uint64_t size) {
#ifdef TAINTDEBUG
    assert(addr + size <= fast_shad->size);
#endif
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
