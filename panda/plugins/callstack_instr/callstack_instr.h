#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

#include "prog_point.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

PPP_CB_TYPEDEF(void, on_call, CPUState *env, target_ulong func);
PPP_CB_TYPEDEF(void, on_ret, CPUState *env, target_ulong func);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif
