#ifndef __STRINGSEARCH_PPP_H_
#define __STRINGSEARCH_PPP_H_


// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// the type for the ppp callback fn that can be passed to string search to be called
// whenever a string match is observed
PPP_CB_TYPEDEF(void, on_ssm, CPUState *env, target_ulong pc, target_ulong addr, uint8_t *matched_string,  uint32_t matched_string_length, bool is_write, bool in_memory);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif
