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

typedef struct LabelSet LabelSet;

typedef enum {
    FAST_SHAD_BIT,
    FAST_SHAD_BYTE,
    FAST_SHAD_WORD
} FastShadGranularity;

typedef struct {
    LabelSet **labels;
} FastShad;

// Allocate a new FastShad. Size sizeof(LabelSet *) * ram_size.
// granularity assumed to be BYTE for now.
FastShad *fast_shad_new(uint64_t addrs, FastShadGranularity granularity);

// release all memory associated with this fast_shad.
void fast_shad_free(FastShad *fast_shad);

// Taint a set of addresses with a labelset.
inline void fast_shad_set(FastShad *fast_shad, uint64_t addr, uint64_t size, LabelSet *ls);

// Bulk copy taint (implemented by memcopy).
inline void fast_shad_copy(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size);

// Query. NULL if untainted.
inline LabelSet *fast_shad_query(FastShad *fast_shad, uint64_t addr);

#endif
