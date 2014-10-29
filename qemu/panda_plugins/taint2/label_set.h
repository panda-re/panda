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

typedef struct {
    bool initialized;
    LabelSet *(*label_set_union)(LabelSet *, LabelSet *);
    LabelSet *(*label_set_singleton)(uint32_t);
} LabelSetApi;

LabelSetApi label_set_api = { false, NULL, NULL };

void init_labelset_api(TaintBackendType backend_type);

#endif
