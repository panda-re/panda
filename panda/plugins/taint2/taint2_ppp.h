#ifndef __TAINT2_PPP_H_
#define __TAINT2_PPP_H_

//#include "addr.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.


typedef void (*on_branch2_t) (Addr, uint64_t);
typedef void (*on_indirect_jump_t) (Addr, uint64_t);
typedef void (*on_taint_change_t) (Addr, uint64_t);
typedef void (*on_taint_prop_t) (Addr, Addr, uint64_t);
typedef void (*on_ptr_load_t) (Addr, uint64_t, uint64_t);
typedef void (*on_ptr_store_t) (Addr, uint64_t, uint64_t);
typedef void (*on_after_load_t) (Addr, uint64_t, uint64_t);
typedef void (*on_after_store_t) (Addr, uint64_t, uint64_t);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif
