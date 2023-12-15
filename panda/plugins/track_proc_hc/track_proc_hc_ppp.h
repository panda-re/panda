#ifndef __TRACK_PROC_HC_PPP_H
#define __TRACK_PROC_HC_PPP_H

#include <glib.h>
#include "panda/plugin.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

PPP_CB_TYPEDEF(void, on_hc_proc_change, struct proc_t* pending_proc, void* arg2);
PPP_CB_TYPEDEF(void, on_hc_proc_exec, CPUState *env, struct proc_t* pending_proc, void* arg2);
PPP_CB_TYPEDEF(void, on_hc_proc_vma_update, struct vma_t vma, void* arg2);


// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif
