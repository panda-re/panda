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

#include <climits>
#include <iostream>
#include <algorithm>
#include "my_mem.h"
#include "my_bool.h"
#include "label_set.h"

#define SB_INLINE inline

static SB_INLINE void bitset_set_max_num_elements(uint32_t m) {
    // ignore it -- max is uint32_t max
}

static SB_INLINE uint32_t bitset_get_max_num_elements(void) {
    return UINT_MAX;
}

/* Iterate over each label in the set until app(label, stuff2) returns non-0 */
static SB_INLINE void bitset_iter(BitSet& bs, int (*app)(uint32_t e, void* stuff1), void* stuff2) {
    uint32_t i = 0;
    for (auto bval : bs){
        if(bval && (0 != app(i, stuff2)) ){
            break;
        }
        i++;
    }
}

// add this member to the bit array
static SB_INLINE void bitset_add(BitSet& bs, uint32_t member) {
    if(bs.size() <= member)
        bs.resize(member+1, 0);
    bs[member] = true;
}

// remove this element from the set
static SB_INLINE void bitset_remove(BitSet& bs, uint32_t member) {
    if (bs.size() <= member) return;
    bs[member] = false;
}

// returns TRUE if bs contains member, FALSE otherwise
static SB_INLINE bool bitset_member(BitSet& bs, uint32_t member) {
    if (bs.size() <= member) return false;
    return bs[member];
}

static SB_INLINE void bitset_erase(BitSet& bs) {
    bs.clear();
}

// returns TRUE if bitset is empty, FALSE otherwise
static SB_INLINE bool bitset_is_empty(BitSet& bs) {
    return std::none_of(bs.begin(), bs.end(), [](bool b){ return b;});
    /*for (auto b : bs){
        if(b) return false;
    }
    return true;*/
}

// make bsDest a copy of bsSrc
static SB_INLINE void bitset_copy_in_place(BitSet& bsDest, BitSet& bsSrc) {
    bsDest = bsSrc;
}

// returns number of elements in the bitset
static SB_INLINE uint32_t bitset_card(BitSet& bs) {
    return std::count(bs.begin(), bs.end(), true);
    /*uint32_t count = 0;
    for (auto b : bs){
        if(b) count++;
    }
    return count;*/
}

// merge bsDest with bsSrc and place result in bsDest
static SB_INLINE void bitset_collect(BitSet& bsDest, BitSet& bsSrc) {
    if (bsDest.size() < bsSrc.size()){
        bsDest.resize(bsSrc.size());
    }
    for (size_t i=0; i < bsSrc.size(); i++){
        bsDest[i] = bsDest[i] || bsSrc[i];
    }
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
    int j = 0;
    for(size_t i = 0 ; i < bs.size(); i++) {
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
