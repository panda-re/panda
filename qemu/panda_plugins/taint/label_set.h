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
//mz #include "bitset.h"

struct BitSet;

typedef struct BitSet BitSet;

// typedef enum {LST_COPY, LST_ADD, LST_COMPUTE, LST_DUNNO} LabelSetType;


#define LST_DUNNO 0
#define LST_COPY 1
#define LST_COMPUTE 2
typedef uint32_t LabelSetType;


typedef struct _label_set_struct {
  BitSet *set;        // the set itself (abstract type)
  LabelSetType type;  // type  
  uint32_t count;
} LabelSet;


// TRL these are all inlined
#if 0

// sets max number of unique labels 
 inline void labelset_set_max_num_labels(uint32_t m);

// retrieve max number of labels
 inline uint32_t labelset_get_max_num_labels();

// returns a new, empty label set
// type is LST_DUNNO initially
 inline LabelSet *labelset_new();

// recycles this label set (avaialble to use by new, but not freed)
//void labelset_recycle(LabelSet *ls);

// frees all labelsets on the recycled list
//void labelset_free_recycled();

// free this label set
 inline void labelset_free(LabelSet *ls);

// clear this labelset -- reset all of its bits. 
// type set to LST_DUNNO
 inline void labelset_erase(LabelSet *ls);

// returns true iff this labelset is empty
inline uint8_t labelset_is_empty(LabelSet *ls);

// add label l to set ls
// NB: we don't set LabelSetType in here.
// -- could be LST_COPY or LST_COMPUTE after this operation, 
// depending upon what it was before.  
// this is true regardless of previous size of set.
// we might add a single lable to a previously empty set and 
// want to call the result a copy. 
 inline void labelset_add(LabelSet *ls, uint32_t l);

// make lsDest a copy of lsSrc
// LabeSetType of dest set to be type of src
//void labelset_copy(LabelSet *lsDest, LabelSet *lsSrc);
// returns a copy of ls
 inline LabelSet *labelset_copy(LabelSet *ls);

// union lsDest with lsSrc and place contents in lsDest
// type of dest becomes LST_COMPUTE
 inline void labelset_union_deprecated(LabelSet *lsDest, LabelSet *lsSrc);

// this union *isnt* in place.  
 inline LabelSet *labelset_union(LabelSet *ls1, LabelSet *ls2);

// returns TRUE iff label l is in set ls.
 inline uint8_t labelset_member(LabelSet *ls, uint32_t l);

// returns cardinality of the set, i.e. num labels
 inline uint32_t labelset_card(LabelSet *ls);

// set label set type
 inline void labelset_set_type(LabelSet *ls, LabelSetType type);

// obtain label set type
 inline LabelSetType labelset_get_type(LabelSet *ls);

// returns TRUE iff this label is of this type
 inline uint8_t labelset_test_type(LabelSet *ls, LabelSetType isItThisType);

// returns ptr to string (please don't try to mutate it) representation of this type
 inline const char *labelset_type_str(LabelSetType type);

// returns list of labels *n_addr long.  allocates for the list
 inline uint32_t *labelset_get_list(LabelSet *ls, uint32_t *n_addr);

// same as previous but el gets the list.  el assumed pre-allocated by caller
 inline void labelset_get_list_here(LabelSet *ls, uint32_t *el);

// apply fn app to every element in this label set.
// stuff2 also gets passed as third arg to app
inline void labelset_iter (LabelSet *ls, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// returns some element of this set 
// NB: returns 0xffffffff if some fool passes in an empty set
inline uint32_t labelset_choose(LabelSet *ls);

 inline void labelset_save(void * /* QEMUFile * */ f, LabelSet *ls);
 inline LabelSet *labelset_load(void * /* QEMUFile * */ f);
#endif

#endif
