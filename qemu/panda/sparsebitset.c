// to test:
// gcc -o sparsebitset_test sparsebitset.c my_mem.c -DSBS_TESTING
// ./sparsebitset_test

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "my_mem.h"
#include "my_bool.h"

#include "label_set.h"

#define RESIZE 2

// really our sparse bitset is a growable array of elements
#ifdef SBS_TESTING
struct BitSet_struct {
#else
struct BitSet {
#endif
  uint32_t max_size;      // max number of elements set can fit currently
  uint32_t current_size;  // current number of elements
  uint32_t *members;      // the members themselves each of which is an integer
};

#ifdef SBS_TESTING
typedef struct BitSet_struct BitSet;
#endif

// NB: BitSet is defined in label_set.h
// Because of when inlining happens this will make the compiler happy.  

#define BITSET_DEFAULT_SIZE 4

#define SB_INLINE inline


// returns a new bitset, initially empty, but with space for 1 member
// NB: this function allocates memory. caller is responsible for freeing.
static SB_INLINE BitSet *bitset_new(void) {
  BitSet *bs;
  bs = (BitSet *) my_malloc(sizeof(BitSet), poolid_sparsebitset);
  //mz Let's make a more sane defalut size
  bs->max_size = BITSET_DEFAULT_SIZE;
  bs->current_size = 0;
  bs->members = (uint32_t *) my_malloc(sizeof(uint32_t) * bs->max_size, poolid_sparsebitset);
  return bs;
}

static SB_INLINE void bitset_set_max_num_elements(uint32_t m) {
  // ignore it -- max is uint32_t max
}


static SB_INLINE uint32_t bitset_get_max_num_elements(void) {
  return UINT_MAX;
}


// destroy this bitset
static SB_INLINE void bitset_free(BitSet *bs) {
  my_free(bs->members, sizeof(uint32_t)*bs->max_size, poolid_sparsebitset);
  my_free(bs, sizeof(BitSet), poolid_sparsebitset);
}

  
static SB_INLINE void bitset_iter (BitSet *bs, int (*app)(uint32_t e, void *stuff1), void *stuff2) {
  uint32_t i;
  for (i=0; i<bs->current_size; i++) {
    if ((app(bs->members[i], stuff2)) != 0) {
      break;
    }
  }    
}

// add this member to the bit array
// NB: this function allocates memory. caller is responsible for freeing.
static SB_INLINE void bitset_add(BitSet *bs, uint32_t member) {
  uint32_t i;
  // is it there already?
  for (i=0; i<bs->current_size; i++) {
    if (bs->members[i] == member) {
      // yes -- done
      return;
    }
  }
  // nope
  if (bs->current_size == bs->max_size) {
    // need more space for members
    uint32_t old_size = bs->max_size;
    bs->max_size *= RESIZE;
    bs->members = 
      (uint32_t *) my_realloc(bs->members, 
			      sizeof(uint32_t) * bs->max_size,
			      old_size,
			      poolid_sparsebitset);
  }
  bs->members[bs->current_size] = member;
  bs->current_size ++;
}
  
  
// remove this element from the set
static SB_INLINE void  bitset_remove(BitSet *bs, uint32_t member) {
  uint32_t i;
  for (i=0; i<bs->current_size; i++) {
    if (bs->members[i] == member) {
      // found it.
      if (i < (bs->current_size-1)) {
        // shift everything to the right of it one index to the left
        uint32_t j;
        for (j=i+1; j<bs->current_size; j++) {
          bs->members[j-1] = bs->members[j];
        }
      }
      bs->current_size --;
      return;
    }
  }
}


// returns TRUE if bs contains member, FALSE otherwise
static SB_INLINE uint8_t bitset_member(BitSet *bs, uint32_t member) {
  uint32_t i;
  for (i=0; i<bs->current_size; i++) {
    if (bs->members[i] == member) return TRUE;
  }
  return FALSE;
}

static SB_INLINE uint32_t bitset_choose(BitSet *bs) {
  if (bs->current_size == 0) {
    return 0xffffffff;
  }
  return bs->members[0];
}


// empty the set.  very fast.
static SB_INLINE void bitset_erase(BitSet *bs) {
#if 1
  if (bs->max_size != BITSET_DEFAULT_SIZE) {
    bs->members = 
      (uint32_t *) my_realloc(bs->members, 
			      sizeof(uint32_t) * BITSET_DEFAULT_SIZE, 
			      sizeof(uint32_t) * bs->max_size, poolid_sparsebitset);
    bs->max_size = BITSET_DEFAULT_SIZE;
  }
#endif
  bs->current_size = 0;
}


// returns TRUE if bitset is empty, FALSE otherwise
static SB_INLINE uint8_t bitset_is_empty(BitSet *bs) {
  return (bs->current_size == 0);
}


// make bsDest a copy of bsSrc
// realloc bs as necessary
static SB_INLINE void bitset_copy_in_place(BitSet *bsDest, BitSet *bsSrc) {
  // grow (or shrink) dest if necessary
  if (bsDest->max_size != bsSrc->max_size) {
    bsDest->members = 
      (uint32_t *) my_realloc(bsDest->members, 
			      sizeof(uint32_t) * bsSrc->max_size,
			      sizeof(uint32_t) * bsDest->max_size,
			      poolid_sparsebitset);
    bsDest->max_size = bsSrc->max_size;
  }
  bsDest->current_size = bsSrc->current_size;
  memcpy(bsDest->members, bsSrc->members, bsSrc->current_size * sizeof(uint32_t));
}


// returns number of elements in the bitset
static SB_INLINE uint32_t bitset_card(BitSet *bs) {
  return bs->current_size;
}


static SB_INLINE void bitset_spit(BitSet *bs);

// union bsDest with lsSrcs and place result in bsDest
static SB_INLINE void bitset_collect(BitSet *bsDest, BitSet *bsSrc) {
  uint32_t i;
  //if (bsSrc->current_size > 200){
  //    return;
  //}
  for (i=0; i<bsSrc->current_size; i++) {
    bitset_add(bsDest, bsSrc->members[i]);
  }
}


// return a new bitset containing the union of bs1 and bs2 
static SB_INLINE BitSet *bitset_union(BitSet *bs1, BitSet *bs2) {
  BitSet *bs_new = bitset_new();
  bitset_collect(bs_new, bs1);
  bitset_collect(bs_new, bs2);
  return bs_new;
}


// return an array of integers *n_addr elements long
// NB: this function allocates memory. caller is responsible for freeing.
static SB_INLINE uint32_t *bitset_get_list(BitSet *bs, uint32_t *n_addr) {
  *n_addr = bs->current_size;
  uint32_t *el = (uint32_t *) my_malloc(sizeof(uint32_t) * bs->current_size, poolid_sparsebitset);
#if 0
  int i;
  for (i=0; i<bs->current_size; i++) {
    el[i] = bs->members[i];
  }
#else
  memcpy(el, bs->members, sizeof(uint32_t) * bs->current_size);
#endif
  return el;
}

// populates el (assumed to be pre-allocated adequately by caller)
// with list of members in bitset bs. 
static SB_INLINE void bitset_get_list_here(BitSet *bs, uint32_t *el) {
#if 0
  int i;
  for (i=0; i<bs->current_size; i++) {
    el[i] = bs->members[i];
  }
#else
  memcpy(el, bs->members, sizeof(uint32_t) * bs->current_size);
#endif
}


// spit out members of the set
static SB_INLINE void bitset_spit(BitSet *bs) {
  uint32_t i;
  for (i=0; i<bs->current_size; i++) {
    printf ("%d ", bs->members[i]);
  }
}

#ifndef NO_QEMU_FILE
#include "../hw/hw.h"

static SB_INLINE int __bitset_save_aux(uint32_t e, void *f) {
  qemu_put_be32(f, e);
  return 0;
}


// save this bitset to qemu file f
static SB_INLINE void bitset_save(void * /* QEMUFile * */ f, BitSet *bs) {
  qemu_put_be32(f, bs->max_size);
  qemu_put_be32(f, bs->current_size);
  bitset_iter(bs, __bitset_save_aux, f);
}


// re-populate this bitset from qemu file bs
// nb: bitset struct already exists
static SB_INLINE void bitset_fill(void * /* QEMUFile * */ f, BitSet *bs) {
  uint32_t old_max_size = bs->max_size;
  bs->max_size = qemu_get_be32(f);
  if (bs->max_size != old_max_size) {
    // resize if necessary
    bs->members = 
      (uint32_t *) my_realloc(bs->members,
			      sizeof(uint32_t) * bs->max_size,
			      sizeof(uint32_t) * old_max_size,			      
			      poolid_sparsebitset);
  }
  bs->current_size = qemu_get_be32(f);
  int i;
  for (i=0; i<bs->current_size; i++) {
    uint32_t e = qemu_get_be32(f);
    bs->members[i] = e;
  }
}


// returns a new bitset read from this file
static SB_INLINE BitSet *bitset_load(void * /* QEMUFile * */ f) {
  BitSet *bs = (BitSet *) my_malloc(sizeof(BitSet), poolid_sparsebitset);
  bs->max_size = qemu_get_be32(f);
  bs->current_size = qemu_get_be32(f);
  bs->members = (uint32_t *) my_malloc(sizeof(uint32_t) * bs->max_size, poolid_sparsebitset);
  int i;
  for (i=0; i<bs->current_size; i++) {
    uint32_t e = qemu_get_be32(f);
    bs->members[i] = e;
  }
  return bs;
}
#endif // NO_QEMU_FILE


#ifdef SBS_TESTING

#define SBS_NUM_TESTS 100
#define SBS_NUM_SETS 100
#define SBS_DUNNO 100

int main (int argc, char **argv) {
  int i,j;

  for (i=1; i<SBS_NUM_TESTS; i++) {
    uint32_t nbits = i;
    bitset_set_max_num_elements(nbits);
    printf ("\n\ni=%d nb=%d\n", i, nbits);
    uint32_t num_bs = SBS_NUM_TESTS;
    BitSet *bs;  //  = (BitSet *) my_malloc(sizeof(BitSet) * num_bs);
    bs = bitset_new();
    /*
    for (j=0; j<num_bs; j++) {
      bs[j] = bitset_new();
    }    
    */
    for (j=0; j<nbits * SBS_DUNNO ; j++) {
      printf ("j=%d\n", j);
      int element = rand() % nbits;
      printf ("set %d\n", element);
      bitset_add(bs,element);
      assert (bitset_member(bs,element));
      bitset_spit(bs);
      printf ("\n");
      element = rand() % nbits;
      printf ("unset %d\n", element);
      bitset_remove(bs,element);
      assert (!(bitset_member(bs,element)));
      bitset_spit(bs);
      printf ("\n");
    }
    bitset_free(bs);
  }
}	     
#endif
