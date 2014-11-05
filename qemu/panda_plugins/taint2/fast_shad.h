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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>

#include "qemu-common.h"
#include "cpu-all.h"
#include "panda_plugin.h"

#include "label_set.h"
#include "fast_shad.h"

FastShad *fast_shad_new(uint64_t bytes, FastShadGranularity granularity) {
    FastShad *result = malloc(sizeof(FastShad));
    if (!result) return NULL;

    LabelSet **array;
    uint64_t size = sizeof(LabelSet *) * bytes;
    uint64_t align = 1 << 40; // Align to a 1T boundary.
    assert(align > size);
    uint64_t vaddr = 0;
    do {
        // We're going to try to make this aligned.
        vaddr += align;
        printf("taint2: Trying to map shadow memory @ 0x%" PRIx64 ".\n", vaddr);
        array = (LabelSet **)mmap((void *)vaddr, size, PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_HUGETLB,
                -1, 0);
        if (array == (LabelSet **)MAP_FAILED) {
            printf("taint2: Hugetlb failed. Trying without.\n");
            // try without HUGETLB
            array = (LabelSet **)mmap((void *)vaddr, size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        }
    } while (array == (LabelSet **)MAP_FAILED && vaddr <= align * 8); // only try 8 times.
    if (array == (LabelSet **)MAP_FAILED) {
        puts(strerror(errno));
        return NULL;
    }

    result->labels = array;
    result->granularity = granularity;
    result->bytes = bytes;

    return result;
}

// release all memory associated with this fast_shad.
void fast_shad_free(FastShad *fast_shad) {
    munmap(result->labels, sizeof(LabelSet *) * fast_shad->bytes);
    free(fast_shad);
}

static inline LabelSet **get_ls_p(FastShad *fast_shad, target_ulong guest_addr) {
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
inline void fast_shad_set(FastShad *fast_shad, target_ulong addr, LabelSet *ls) {
    *get_ls_p(fast_shad, addr) = ls;
}

inline void fast_shad_copy(FastShad *fast_shad_dest, uint64_t dest, FastShad *fast_shad_src, uint64_t src, uint64_t size) {
    memcpy(get_ls_p(fast_shad_dest, dest), get_ls_p(fast_shad_src, src), size);
}

// Remove taint.
inline void fast_shad_remove(FastShad *fast_shad, target_ulong addr) {
    *get_ls_p(fast_shad, addr) = NULL;
}

// Query. NULL if untainted.
inline LabelSet *fast_shad_query(FastShad *fast_shad, target_ulong addr) {
    return *get_ls_p(fast_shad, addr);
} 

#endif
