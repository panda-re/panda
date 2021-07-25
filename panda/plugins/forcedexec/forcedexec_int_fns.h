#ifndef __FORCEDEXEC_INT_FNS_H__
#define __FORCEDEXEC_INT_FNS_H__

#include "forcedexec_ppp.h"

extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

extern "C" void enable_forcedexec();
extern "C" void disable_forcedexec();

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}
#endif
