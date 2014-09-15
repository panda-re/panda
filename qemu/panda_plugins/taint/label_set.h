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

#include <numeric> //std::iota
#include <cstdint>
#include "my_mem.h"

typedef uint32_t LabelSetType;
enum LabelSetTypes {
    LST_DUNNO = 0,
    LST_COPY = 1,
    LST_COMPUTE = 2,
};

#if defined(LABELSET_VECTOR)
#include <vector>
typedef std::vector<bool,mymem_allocator<bool, poolid_bitset>> BitSet;
#define BITSET_IMPLEMENTATION "vectorbitset.cpp"
#elif defined(LABELSET_STDBITSET)
#include <bitset>
constexpr static inline uint32_t bitset_get_max_num_elements(void) {
#if defined(LABELSET_MAX_LABELS)
    return LABELSET_MAX_LABELS;
#else
    return 256;
#endif
}
typedef std::bitset<bitset_get_max_num_elements()> BitSet;
#define BITSET_IMPLEMENTATION "stdbitset.cpp"

#else
#include <set>
typedef std::set<uint32_t,std::less<uint32_t>,mymem_allocator<uint32_t, poolid_bitset>> BitSet;
#define BITSET_IMPLEMENTATION "sparsebitset.cpp"
#endif

struct LabelSet {
    BitSet set;         // the set itself (C++ Set)
    LabelSetType type;  // type
    uint32_t count;
    inline bool isCompute(void){
        return this->type >= LST_COMPUTE;
    }
};

#endif
