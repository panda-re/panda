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

/*
   to test:

   simple, full bitsets
   gcc -o bitset_label_set_test bitvector_label_set.c bitset.c prob.c my_mem.c -D BVLS_TESTING
   ./bitset_label_set_test

   sparse bitsets
   gcc -o sparsebitset_label_set_test bitvector_label_set.c sparsebitset.c prob.c \
   my_mem.c -D BVLS_TESTING
   ./sparsebitset_label_set_test
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "my_mem.h"
#include "my_bool.h"
#include "max.h"
#include "label_set.h"
#include "sparsebitset.cpp"

#ifdef BVLS_TESTING
extern "C" {
#include "prob.h"
}
static uint8_t bv_debug = 0;
#endif

#define SB_INLINE inline

extern uint32_t max_ref_count;

static const char *label_set_type_str[] = {"copy","add","compute","dunno"};

static SB_INLINE const char *labelset_type_str(LabelSetType type) {
    return label_set_type_str[type];
}

// create a new labelset and return it
// NB: this function allocates memory. caller is responsible for freeing.
static SB_INLINE LabelSet *labelset_new(void) {
    LabelSet *ls;
    ls = (LabelSet *) my_calloc(1, sizeof(LabelSet), poolid_label_set);
    ls->set = bitset_new();
    ls->type = LST_DUNNO;
    ls->count = 1;
    return ls;
}

// set maximum number of unique labels
static SB_INLINE void labelset_set_max_num_labels(uint32_t m) {
    bitset_set_max_num_elements(m);
}

// retrieve max number of labels
static SB_INLINE uint32_t labelset_get_max_num_labels(void) {
    return bitset_get_max_num_elements();
}

static SB_INLINE void labelset_set_type(LabelSet *ls, LabelSetType type) {
    ls->type = type;
}

// add one to length of derivation
static SB_INLINE void labelset_inc_type(LabelSet *ls) {
    // we'd want to know if this ever overflows...
    assert (ls->type < UINT_MAX);
    ls->type ++;
}

static SB_INLINE LabelSetType labelset_get_type(LabelSet *ls) {
    return ls->type;
}

static SB_INLINE bool labelset_is_compute(LabelSet *ls) {
    return (ls->type > LST_COPY);
}

static SB_INLINE bool labelset_test_type(LabelSet *ls, LabelSetType isItThisType) {
    return (ls->type == isItThisType);
}

// free this labelset (assumes no ptrs held)
static SB_INLINE void labelset_free(LabelSet *ls) {
    if (ls == NULL) return;
    assert (ls->count > 0);
    ls->count--;
    if (ls->count == 0) {
        // ref count went to zero -- really free
        bitset_free(*(ls->set));
        my_free(ls, sizeof(LabelSet), poolid_label_set);
    }
}

// clear this labelset -- reset all of its bits.
static SB_INLINE void labelset_erase(LabelSet *ls) {
    bitset_erase(*(ls->set));
    ls->type = LST_DUNNO;
}

// returns true iff this labelset is empty
static SB_INLINE bool labelset_is_empty(LabelSet *ls) {
    if (ls == 0) return true;
    return bitset_is_empty(*(ls->set));
}

// returns TRUE iff label l is in set ls.
static SB_INLINE bool labelset_member(LabelSet *ls, uint32_t l) {
    return bitset_member(*(ls->set),l);
}

static SB_INLINE uint32_t labelset_card(LabelSet *ls) {
    return bitset_card(*(ls->set));
}

// add label l to set ls
// NB: this function allocates memory, sometimes, when calling bitset_add.
static SB_INLINE void labelset_add(LabelSet *ls, uint32_t l) {
    bitset_add(*(ls->set), l);
    // NB: we don't set LabelSetType in here.
    // -- could be LST_COPY or LST_COMPUTE after this operation,
    // depending upon what it was before.
    // this is true regardless of previous size of set.
    // we might add a single label to a previously empty set and
    // still want to call the result a copy.
    // assume this is managed at call site or higher up.
}

// really we just return the pointer and keep track of # of refs.
static SB_INLINE LabelSet *labelset_copy(LabelSet *ls) {
    if (ls == NULL) {
        return NULL;
    }
    ls->count ++;
    if (ls->count > max_ref_count) {
        max_ref_count = ls->count;
    }
    return ls;
}

// here we actually make a copy
static SB_INLINE LabelSet *labelset_copy_real(LabelSet *ls) {
    LabelSet *ls_copy = labelset_new();
    bitset_copy_in_place(*(ls_copy->set), *(ls->set));
    // must propagate label set type, too
    ls_copy->type = ls->type;
    assert (ls->type != LST_DUNNO);
    return ls_copy;
}

// here we actually make a copy in place
static SB_INLINE void labelset_copy_in_place(LabelSet *lsDest, LabelSet *lsSrc) {
    bitset_copy_in_place(*(lsDest->set), *(lsSrc->set));
    // must propagate label set type, too
    assert (lsSrc->type != LST_DUNNO);
    lsDest->type = lsSrc->type;
}

// iterate over items in this labelset and apply fn app to each.
// stuff2 also gets passed to app
static SB_INLINE void labelset_iter (LabelSet *ls, int (*app)(uint32_t el, void *stuff1), void *stuff2) {
    bitset_iter(*(ls->set), app, stuff2);
}

// union lsDest with lsSrc and place contents in lsDest
// NB: this function allocates memory, sometimes, when calling bitset_union
static SB_INLINE void labelset_collect(LabelSet *lsDest, LabelSet *lsSrc) {
    if (lsDest == NULL || lsSrc == NULL) {
        return;
    }
    bitset_collect(*(lsDest->set),*(lsSrc->set));
    lsDest->type = 1+max(lsDest->type, lsSrc->type);
    assert (lsDest->type != LST_DUNNO);
    assert (lsSrc->type != LST_DUNNO);
}

// form a new set that is the union of ls1 and ls2
static SB_INLINE LabelSet *labelset_union(LabelSet *ls1, LabelSet *ls2) {
    LabelSet *ls_new;
    ls_new = (LabelSet *) my_calloc(1, sizeof(LabelSet), poolid_label_set);
    ls_new->set = (BitSet *) bitset_union(*(ls1->set), *(ls2->set));
    ls_new->count = 1;
    assert (ls1->type != LST_DUNNO);
    assert (ls2->type != LST_DUNNO);
    ls_new->type = 1+max(ls1->type, ls2->type);
    assert (ls_new->type != LST_DUNNO);
    return ls_new;
}

static SB_INLINE void labelset_spit(LabelSet *ls) {
    assert(ls->set != NULL);
    bitset_spit(*(ls->set));
}

// returns list of labels *n_addr long
static SB_INLINE uint32_t *labelset_get_list(LabelSet *ls, uint32_t *n_addr) {
    return bitset_get_list(*(ls->set), n_addr);
}

static SB_INLINE uint32_t labelset_choose(LabelSet *ls) {
    return bitset_choose(*(ls->set));
}

// returns list of labels *n_addr long.  el is pre-allocated
static SB_INLINE void labelset_get_list_here(LabelSet *ls, uint32_t *el) {
    return bitset_get_list_here(*(ls->set), el);
}

/*
#ifndef NO_QEMU_FILE
static SB_INLINE void labelset_save(void * f, LabelSet *ls) {
qemu_put_be32(f, ls->type);
bitset_save(f, ls->set);
}

static SB_INLINE void labelset_fill(void * f, LabelSet *ls) {
ls->type = qemu_get_be32(f);
bitset_fill(f, ls->set);
}

static SB_INLINE LabelSet *labelset_load(void * f) {
LabelSet *ls = (LabelSet *) my_malloc(sizeof(LabelSet), poolid_label_set);
ls->type = qemu_get_be32(f);
ls->set = bitset_load(f);
return ls;
}
#endif
*/

#ifdef BVLS_TESTING

typedef enum ops
{
    ERASE,
    IS_EMPTY,
    ADD,
    COPY,
    UNION
} OP;

#define NUM_OPS 5

void spit(int l, LabelSet **ls) {
    printf ("set %d: [",l);
    labelset_spit(ls[l]);
    printf ("]\n");
}

int main (int argc, char **argv) {
    int i=0,j=0;
    uint32_t num_tests, num_sets_per_test, num_ops_per_test, the_max_num_labels, seed;
    uint8_t x=0;
    uint32_t y=0,zz=0;
    Dpdf *pdf=NULL;
    int num_args = 6;

    if (argc-1 == num_args) {
        num_tests = atoi(argv[1]);
        num_sets_per_test = atoi(argv[2]);
        num_ops_per_test = atoi(argv[3]);
        the_max_num_labels = atoi(argv[4]);
        seed = atoi(argv[5]);
        bv_debug = atoi(argv[6]);
    }
    else {
        printf ("I needed %d args; you provided %d -- using defaults.\n", num_args, argc-1);
        printf ("usage: bvlt num_tests num_sets_per_test num_ops_per_test max_labels seed bv_debug\n");
        num_tests = 10;
        num_sets_per_test = 10;
        num_ops_per_test = 1000;
        the_max_num_labels = 32;
        seed = 1234567;
        bv_debug =  TRUE;
    }

    printf ("%d tests\n", num_tests);
    printf ("%d sets per test\n", num_sets_per_test);
    printf ("%d ops per test\n", num_ops_per_test);
    printf ("%d max unique labels\n", the_max_num_labels);
    printf ("%d random seed\n", seed);

    pdf = prob_create("bvc",NUM_OPS);
    prob_set(pdf,ERASE,0.05);
    prob_set(pdf,IS_EMPTY,0.05);
    prob_set(pdf,ADD,0.5);
    prob_set(pdf,COPY,0.05);
    prob_set(pdf,UNION,0.05);
    prob_normalize(pdf);
    printf ("dist of ops {ERASE,IS_EMPTY,ADD,COPY,UNION}\n ");
    prob_spit(pdf);

    srand(seed);
    labelset_set_max_num_labels(the_max_num_labels);
    for (i=0; i<num_tests; i++) {
        if (bv_debug) printf ("test %d\n", i);
        LabelSet **ls = (LabelSet **) my_malloc(sizeof(LabelSet *) * num_sets_per_test, poolid_label_set);
        for (j=0; j<num_sets_per_test; j++) {
            ls[j] = labelset_new();
        }
        for (j=0; j<num_ops_per_test; j++) {
            if (bv_debug) printf ("op %d: ", j);
            uint32_t l = random() % num_sets_per_test;
            int d = prob_draw(pdf);
            LabelSet *tls = ls[l];
            switch (d) {
                case ERASE:
                    labelset_erase(tls);
                    assert ((labelset_card(tls)) == 0);
                    if (bv_debug) {
                        printf ("erase set %d. ",l);
                        spit (l,ls);
                    }
                    break;
                case IS_EMPTY:
                    x = labelset_is_empty(tls);
                    if (x)
                        assert ((labelset_card(tls)) == 0);
                    else
                        assert ((labelset_card(tls)) != 0);
                    if (bv_debug) {
                        printf ("is_empty set=%d: %d. ", l, x);
                        spit (l,ls);
                    }
                    break;
                case ADD:
                    {
                        uint32_t n1 = labelset_card(tls);
                        uint32_t y = (random()) % the_max_num_labels;
                        uint8_t already_there = labelset_member(tls,y);
                        labelset_add(tls,y);
                        assert (labelset_member(tls,y));
                        uint32_t n2 = labelset_card(tls);
                        if (already_there)
                            assert (n1 == n2);
                        else
                            assert (n1 + 1 == n2);
                        if (bv_debug) {
                            printf ("add to set=%d, el=%d. ",l,y);
                            spit(l,ls);
                        }
                        break;
                    }
                case COPY:
                    {
                        uint32_t o=0;
                        do {
                            o = random() % num_sets_per_test;
                        } while (o == l);
                        labelset_copy(tls,ls[o]);
                        if (bv_debug) {
                            printf ("copy set=%d to set=%d. ",o,l);
                            spit(l,ls);
                        }
                        break;
                    }
                case UNION:
                    {
                        uint32_t o=0;
                        do {
                            o = random() % num_sets_per_test;
                        } while (o == l);
                        labelset_union(tls,ls[o]);
                        if (bv_debug) {
                            printf ("union set=%d <- set=%d. ", l,o);
                            spit(l,ls);
                        }
                        break;
                    }
                default:
                    printf ("wtf d=%d\n", d);
                    abort();
                    break;
            }
            zz += x; // make sure x actually gets computed.
        } // iterate over ops
        // release memory
        for (j=0; j<num_sets_per_test; j++) {
            labelset_free(ls[j]);
        }
        my_free(ls, sizeof(LabelSet), poolid_label_set);
    } // iterate over tests
    printf ("zz=%d\n", zz); // say no to optimizers
    prob_destroy(pdf);
} // main

#endif // BVLS_TESTING
