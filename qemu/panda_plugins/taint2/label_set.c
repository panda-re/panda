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

#include "label_set.h"
#include "my_mem.h"

static inline LabelSet *label_set_union(LabelSet *ls1, LabelSet *ls2) {
    if (ls1 && ls2) {
        LabelSet *result = my_malloc(sizeof(LabelSet), poolid_label_set);
        result->refcount = 1;
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
    LabelSet *result = my_malloc(sizeof(LabelSet), poolid_label_set);
    result->refcount = 1;
    result->child1 = NULL;
    result->label = label;
    return result;
}

// Binary taint represented by non-null labelset pointer.
static inline LabelSet *binary_set_union(LabelSet *ls1, LabelSet *ls2) {
    if (ls1) return ls1;
    else return ls2;
}

static inline LabelSet *binary_set_singleton(uint32_t label) {
    return (LabelSet *)true;
}

void init_labelset_api(TaintBackendType backend_type) {
    label_set_api.initialized = true;
    switch (backend_type) {
        case TAINT_BACKEND_LABEL:
            label_set_api.label_set_union = label_set_union;
            label_set_api.label_set_singleton = label_set_singleton;
            break;
        case TAINT_BACKEND_BINARY:
            label_set_api.label_set_union = binary_set_union;
            label_set_api.label_set_singleton = binary_set_singleton;
            break;
        default:
            assert(false);
    }
}
