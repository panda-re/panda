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

#include "my_mem.h"

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    TAINT_BACKEND_BINARY,
    TAINT_BACKEND_LABEL
} TaintBackendType;

// We use the same type for different backends for programming convenience.
// This enables us to avoid dlopen/dlsym whatever.
typedef struct LabelSet {
    struct LabelSet *child1;
    union {     // If child1 is null this is a number.
        struct LabelSet *child2;
        uint32_t label;
    };
} LabelSet;

/*
inline LabelSet *label_set_union(LabelSet *ls1, LabelSet *ls2);
inline LabelSet *label_set_singleton(uint32_t label);
inline uint32_t label_set_cardinality(LabelSet *ls);
*/

static inline LabelSet *label_set_union(LabelSet *ls1, LabelSet *ls2) {
    if (ls1 == ls2) {
        return ls1;
    } else if (ls1 && ls2) {
        LabelSet *result = (LabelSet *)my_malloc(sizeof(LabelSet), poolid_label_set);
        result->child1 = ls1;
        result->child2 = ls2;
        return result;
    } else if (ls1) {
        return ls1;
    } else if (ls2) {
        return ls2;
    } else return NULL;
}

static inline LabelSet *label_set_singleton(uint32_t label) {
    LabelSet *result = (LabelSet *)my_malloc(sizeof(LabelSet), poolid_label_set);
    result->child1 = NULL;
    result->label = label;
    return result;
}

static inline uint32_t label_set_cardinality(LabelSet *ls) {
    if (ls == NULL) return 0;
    else if (ls->child1 != NULL) {
        return label_set_cardinality(ls->child1) +
            label_set_cardinality(ls->child2);
    } else return 1;
}

#endif
