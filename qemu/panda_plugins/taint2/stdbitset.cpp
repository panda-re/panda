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

#include <iostream>
#include "my_mem.h"
#include "label_set.h"

#define SB_INLINE inline
#define BITSET_BOUNDS_CHECK

static SB_INLINE void bitset_set_max_num_elements(uint32_t m) {
    if(m > bitset_get_max_num_elements()) assert(0);
    return;
}

/* Iterate over each label in the set until app(label, stuff2) returns non-0 */
static SB_INLINE void bitset_iter(BitSet& bs, int (*app)(uint32_t e, void* stuff1), void* stuff2) {
    for (uint32_t i = 0; i < bs.size(); i++){
        if(bs[i] && (0 != app(i, stuff2) )){
            break;
        }
    }
}

// add this member to the bit array
static SB_INLINE void bitset_add(BitSet& bs, uint32_t member) {
#if defined(BITSET_BOUNDS_CHECK)
    assert(member < bs.size()); //std:;bitset::size() is a constexpr
#endif
    bs[member] = true;
}

// remove this element from the set
static SB_INLINE void bitset_remove(BitSet& bs, uint32_t member) {
#if defined(BITSET_BOUNDS_CHECK)
    assert(member < bs.size()); //std:;bitset::size() is a constexpr
#endif
    bs[member] = false;
}

// returns TRUE if bs contains member, FALSE otherwise
static SB_INLINE bool bitset_member(BitSet& bs, uint32_t member) {
#if defined(BITSET_BOUNDS_CHECK)
    assert(member < bs.size()); //std:;bitset::size() is a constexpr
#endif
    return bs[member];
}

static SB_INLINE void bitset_erase(BitSet& bs) {
    bs.reset();
}

// returns TRUE if bitset is empty, FALSE otherwise
static SB_INLINE bool bitset_is_empty(BitSet& bs) {
    return bs.none();
}

// make bsDest a copy of bsSrc
static SB_INLINE void bitset_copy_in_place(BitSet& bsDest, BitSet& bsSrc) {
    bsDest = bsSrc;
}

// returns number of elements in the bitset
static SB_INLINE uint32_t bitset_card(BitSet& bs) {
    return bs.count();
}

// merge bsDest with bsSrc and place result in bsDest
static SB_INLINE void bitset_collect(BitSet& bsDest, BitSet& bsSrc) {
    bsDest |= bsSrc;
}

// return a new bitset containing the union of bs1 and bs2
static SB_INLINE BitSet bitset_union(BitSet& bs1, BitSet& bs2) {
    BitSet bs_new;
    bitset_collect(bs_new, bs1);
    bitset_collect(bs_new, bs2);
    return bs_new;
}

// populates el (assumed to be pre-allocated adequately by caller)
// with list of members in bitset bs.
static SB_INLINE void bitset_get_list_here(BitSet& bs, uint32_t *el) {
    uint32_t j = 0;
    for(uint32_t i = 0 ; i < bs.size(); i++) {
        if(bs[i]){
            el[j] = i;
            j++;
        } 
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
    for(size_t i = 0; i < bs.size(); i++) {
        if(bs[i]) std::cout << i << std::endl;
    }
}
