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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <sys/mman.h>

#include "defines.h"
#include "fast_shad.h"

#include <set>

typedef const std::set<uint32_t> *LabelSetP;

FastShad::FastShad(uint64_t labelsets) {
    uint64_t bytes = sizeof(TaintData) * labelsets;

    TaintData *array;
    if (labelsets < (1UL << 24)) {
        array = (TaintData *)malloc(bytes);
        printf("taint2: Allocating small fast_shad (%" PRIu64 " bytes) using malloc @ %lx.\n",
                bytes, (uint64_t)array);
        assert(array);
        memset(array, 0, bytes);
    } else {
        uint64_t align = 1UL << 40; // Align to a 1T boundary.
        assert(align > bytes);
        uint64_t vaddr = 0;
        do {
            // We're going to try to make this aligned.
            vaddr += align;
            printf("taint2: Allocating large fast_shad (%lu bytes)  @ 0x%" PRIx64 ".\n",
                    bytes, vaddr);
            array = (TaintData *)mmap((void *)vaddr, bytes, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_HUGETLB,
                    -1, 0);
            if (array == (TaintData *)MAP_FAILED) {
                printf("taint2: Hugetlb failed. Trying without.\n");
                // try without HUGETLB
                array = (TaintData *)mmap((void *)vaddr, bytes, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
            }
        } while (array == (TaintData *)MAP_FAILED && vaddr <= align * 8); // only try 8 times.
        if (array == (TaintData *)MAP_FAILED) {
            puts(strerror(errno));
        }
    }

    labels = array;
    orig_labels = array;
    size = labelsets;
}

// release all memory associated with this fast_shad.
FastShad::~FastShad() {
    if (size < (1UL << 24)) {
        free(orig_labels);
    } else {
        munmap(orig_labels, sizeof(TaintData) * size);
    }
}
