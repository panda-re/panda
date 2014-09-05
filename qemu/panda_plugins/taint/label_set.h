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

#include <set>
#include <numeric> //std::iota
#include <cstdint>
#include "my_mem.h"

typedef uint32_t LabelSetType;
enum LabelSetTypes {
    LST_DUNNO = 0,
    LST_COPY = 1,
    LST_COMPUTE = 2,
};

typedef std::set<uint32_t,std::less<uint32_t>,mymem_allocator<uint32_t, poolid_bitset>> BitSet;

struct LabelSet {
    BitSet set;         // the set itself (C++ Set)
    LabelSetType type;  // type
    uint32_t count;
    inline bool isCompute(void){
        return this->type >= LST_COMPUTE;
    }
};

#endif
