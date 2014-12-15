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

#ifndef __LABEL_SET_H_
#define __LABEL_SET_H_

#include <cstdio>

extern "C" {
#include "cpu.h"
#include "qemu-log.h"
}

#include <cstdint>

#include <map>

extern "C" {
typedef struct LabelSet {
    struct LabelSet *child1;
    union {     // If child1 is null this is a number.
        struct LabelSet *child2;
        uint32_t label;
    };
} *LabelSetP;
}

LabelSetP label_set_union(LabelSetP ls1, LabelSetP ls2);
LabelSetP label_set_singleton(uint32_t label);
void label_set_iter(LabelSetP ls, void (*leaf)(uint32_t, void *), void *user);

#endif
