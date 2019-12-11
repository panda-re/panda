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

#include "taint_defines.h"
#include "shad.h"

#include <set>
#include <string>

Shad::Shad(std::string name, uint64_t max_size)
{
    this->_name = name;
    this->size = max_size;
}

Shad::~Shad() = default;

typedef const std::set<uint32_t> *LabelSetP;

FastShad::FastShad(std::string name, uint64_t labelsets) : Shad(name, labelsets)
{
    uint64_t bytes = sizeof(TaintData) * labelsets;

    TaintData *array;
    if (labelsets < (1UL << 24)) {
        array = (TaintData *)malloc(bytes);
        printf("taint2: Allocating small fast_shad (%" PRIu64 " bytes) using malloc @ %p.\n",
                bytes, array);
        assert(array);
        memset(array, 0, bytes);
    } else {
        printf("taint2: Allocating large fast_shad (%" PRIu64 " bytes).\n", bytes);
        array = (TaintData *)mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
        if (array == (TaintData *)MAP_FAILED) {
            puts(strerror(errno));
        }
    }

    labels = array;
    orig_labels = array;
}

// release all memory associated with this fast_shad.
FastShad::~FastShad() {
    if (size < (1UL << 24)) {
        free(orig_labels);
    } else {
        munmap(orig_labels, sizeof(TaintData) * size);
    }
}

LazyShad::LazyShad(std::string name, uint64_t max_size) : Shad(name, max_size)
{
    tassert(this->size > 0);
    tassert(this->_name.size() > 0);
}

LazyShad::~LazyShad()
{
}
