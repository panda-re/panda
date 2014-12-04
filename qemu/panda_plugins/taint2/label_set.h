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

#include <stdint.h>
#include <stdbool.h>

typedef struct LabelSet {
    struct LabelSet *child1;
    union {     // If child1 is null this is a number.
        struct LabelSet *child2;
        uint32_t label;
    };
} LabelSet;

inline LabelSet *label_set_union(LabelSet *ls1, LabelSet *ls2);
inline LabelSet *label_set_singleton(uint32_t label);
static void label_set_iter(LabelSet *ls, void (*iter)(uint32_t, void *), void *user);

inline LabelSet *label_set_union(LabelSet *ls1, LabelSet *ls2) {
    if (ls1 == ls2) {
        return ls1;
    } else if (ls1 && ls2) {
        LabelSet *result = (LabelSet *)malloc(sizeof(LabelSet));
        //labelset_count++;

        result->child1 = ls1;
        result->child2 = ls2;
        return result;
    } else if (ls1) {
        return ls1;
    } else if (ls2) {
        return ls2;
    } else return NULL;
}

inline LabelSet *label_set_singleton(uint32_t label) {
    LabelSet *result = (LabelSet *)malloc(sizeof(LabelSet));
    //labelset_count++;

    result->child1 = NULL;
    result->label = label;
    return result;
}

static void label_set_iter(LabelSet *ls, void (*iter)(uint32_t, void *), void *user) {
    if (!ls) return;
    
    if (ls->child1) { // union
        label_set_iter(ls->child1, iter, user);
        label_set_iter(ls->child2, iter, user);
    } else {
        iter(ls->label, user);
    }
}

#endif
