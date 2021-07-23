#ifndef __ASIDSTORY_H_
#define __ASIDSTORY_H_

#include "osi/osi_types.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// the type for the ppp callback for when asidstory decides a process has changed
// and we have decent OsiProc.
typedef void (*on_proc_change_t)(CPUState *env, target_ulong asid, OsiProc *proc);


// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif 
