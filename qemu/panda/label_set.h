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
#include <stdint.h>
#include "my_mem.h"

#define LST_DUNNO 0
#define LST_COPY 1
#define LST_COMPUTE 2
typedef uint32_t LabelSetType;
typedef std::set<uint32_t> BitSet;

typedef struct _label_set_struct {
  BitSet *set;        // the set itself (C++ Set)
  LabelSetType type;  // type
  uint32_t count;
} LabelSet;

#endif
