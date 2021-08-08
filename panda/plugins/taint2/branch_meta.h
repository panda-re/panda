#ifndef __BRANCH_META_H__
#define __BRANCH_META_H__
#include "taint2.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

typedef struct SymbolicBranchMeta {
    uint64_t pc;
} SymbolicBranchMeta;

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif