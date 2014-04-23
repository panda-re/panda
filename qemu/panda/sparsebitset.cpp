#include <climits>
#include <iostream>
#include <algorithm>
#include "my_mem.h"
#include "my_bool.h"
#include "label_set.h"

#define SB_INLINE inline

// returns a new bitset, initially empty, but with space for 1 member
// NB: this function allocates memory. caller is responsible for freeing.
static SB_INLINE BitSet* bitset_new(void) {
    return new BitSet();
}

static SB_INLINE void bitset_set_max_num_elements(uint32_t m) {
    // ignore it -- max is uint32_t max
}

static SB_INLINE uint32_t bitset_get_max_num_elements(void) {
    //std::set has a max_size method but would require passing in a BitSet
    return UINT_MAX;
}

// destroy this bitset
static SB_INLINE void bitset_free(BitSet& bs) {
    delete &bs;
}

static SB_INLINE void bitset_iter(BitSet& bs, int (*app)(uint32_t e, void* stuff1), void* stuff2) {
    BitSet::iterator i;
    for(i = bs.begin(); i != bs.end(); i++) {
        if((app(*i, stuff2)) != 0) {
            break;
        }
    }
}

// add this member to the bit array
static SB_INLINE void bitset_add(BitSet& bs, uint32_t member) {
    bs.insert(member);
}

// remove this element from the set
static SB_INLINE void bitset_remove(BitSet& bs, uint32_t member) {
    bs.erase(member);
}

// returns TRUE if bs contains member, FALSE otherwise
static SB_INLINE bool bitset_member(BitSet& bs, uint32_t member) {
    return (bs.find(member) == bs.end());
}

static SB_INLINE uint32_t bitset_choose(BitSet& bs) {
    if (bs.size() == 0) return 0xffffffff;
    return *(bs.begin());
}

static SB_INLINE void bitset_erase(BitSet& bs) {
    bs.clear();
}

// returns TRUE if bitset is empty, FALSE otherwise
static SB_INLINE bool bitset_is_empty(BitSet& bs) {
    return bs.empty();
}

// make bsDest a copy of bsSrc
static SB_INLINE void bitset_copy_in_place(BitSet& bsDest, BitSet& bsSrc) {
    bsDest = bsSrc;
}

// returns number of elements in the bitset
static SB_INLINE uint32_t bitset_card(BitSet& bs) {
    return bs.size();
}

// merge bsDest with bsSrc and place result in bsDest
static SB_INLINE void bitset_collect(BitSet& bsDest, BitSet& bsSrc) {
    bsDest.insert(bsSrc.begin(), bsSrc.end());
}

// return a new bitset containing the union of bs1 and bs2
static SB_INLINE BitSet* bitset_union(BitSet& bs1, BitSet& bs2) {
    BitSet *bs_new = new BitSet();
    bitset_collect(*bs_new, bs1);
    bitset_collect(*bs_new, bs2);
    return bs_new;
}

// populates el (assumed to be pre-allocated adequately by caller)
// with list of members in bitset bs.
static SB_INLINE void bitset_get_list_here(BitSet& bs, uint32_t *el) {
    int j = 0;
    BitSet::iterator i;
    for(i = bs.begin(); i != bs.end(); i++) {
        el[j] = *i;
        j++;
    }
}

// return an array of integers *n_addr elements long
static SB_INLINE uint32_t *bitset_get_list(BitSet& bs, uint32_t *n_addr) {
    uint32_t *el = new uint32_t[bs.size()];
    bitset_get_list_here(bs, el);
    return el;
}

// spit out members of the set
static SB_INLINE void bitset_spit(BitSet& bs) {
    BitSet::iterator i;
    for(i = bs.begin(); i != bs.end(); i++) {
        std::cout << *i << std::endl;
    }
}

/*
#ifndef NO_QEMU_FILE
#include "../hw/hw.h"

static SB_INLINE int __bitset_save_aux(uint32_t e, void *f) {
    qemu_put_be32(f, e);
    return 0;
}

// save this bitset to qemu file f
static SB_INLINE void bitset_save(void * f, BitSet& bs) {
    qemu_put_be32(f, bs.max_size());
    qemu_put_be32(f, bs.size());
    bitset_iter(bs, __bitset_save_aux, f);
}

// re-populate this bitset from qemu file bs
// nb: bitset struct already exists
static SB_INLINE void bitset_fill(void * f, BitSet& bs) {
    bs.clear();
    uint32_t max_size = qemu_get_be32(f);
    uint32_t size = qemu_get_be32(f);
    for (int i=0; i < size; i++) {
        uint32_t e = qemu_get_be32(f);
        bs.insert(e);
    }
}

// returns a new bitset read from this file
static SB_INLINE BitSet* bitset_load(void * f) {
    BitSet *bs = new BitSet();
    bitset_fill(f, bs);
    return bs;
}

#endif // NO_QEMU_FILE
*/
