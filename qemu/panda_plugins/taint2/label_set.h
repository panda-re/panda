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

extern "C" {
#include "cpu.h"
#include "qemu-log.h"
}

#include <cstdio>
#include <cstdint>

#include <map>
#include <set>

extern "C" {
typedef struct LabelSet {
    struct LabelSet *child1;
    union {     // If child1 is null this is a number.
        struct LabelSet *child2;
        uint32_t label;
    };

    uint64_t count;
} *LabelSetP;
}

LabelSetP label_set_union(LabelSetP ls1, LabelSetP ls2);
LabelSetP label_set_singleton(uint32_t label);
void label_set_iter(LabelSetP ls, void (*leaf)(uint32_t, void *), void *user);
std::set<uint32_t> label_set_render_set(LabelSetP ls);
uint64_t label_set_render_uint(LabelSetP ls);

template<typename user_type, void (*leaf)(uint32_t, user_type &)>
static void label_set_iter_rec(LabelSetP ls, user_type &user) {
    if (!ls->child1) {
        leaf(ls->label, user);
        return;
    }

    label_set_iter_rec<user_type, leaf>(ls->child1, user);
    label_set_iter_rec<user_type, leaf>(ls->child2, user);
}
    

template<typename user_type, void (*leaf)(uint32_t, user_type &), user_type initial>
static user_type label_set_iter(LabelSetP ls) {
    if (!ls) return initial;

    user_type initial_copy = initial;
    label_set_iter_rec<user_type, leaf>(ls, initial_copy);

    return initial_copy;
}

template<typename user_type, void (*leaf)(uint32_t, user_type &)>
static user_type label_set_iter(LabelSetP ls) {
    user_type initial;

    if (!ls) return initial;

    label_set_iter_rec<user_type, leaf>(ls, initial);

    return initial;
}

__attribute__((unused))
static inline void set_insert(uint32_t l, std::set<uint32_t> &s) {
    s.insert(l);
}

__attribute__((unused))
static inline void bitset_insert(uint32_t l, uint64_t &s) {
    s |= (1UL << l);
}

std::set<uint32_t> label_set_render_set(LabelSetP ls);
uint64_t label_set_render_uint(LabelSetP ls);

#endif
