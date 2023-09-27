#ifndef __CALLWITHARG_H
#define __CALLWITHARG_H

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

PPP_CB_TYPEDEF(void, on_call_match_num, CPUState *env, target_ulong func_addr, target_ulong *args, uint matching_idx, uint args_read);
PPP_CB_TYPEDEF(void, on_call_match_str, CPUState *env, target_ulong func_addr, target_ulong *args, char* value, uint matching_idx, uint args_read);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif

