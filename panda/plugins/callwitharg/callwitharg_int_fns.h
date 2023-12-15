#ifndef __CALLWITHARG_INT_FNS_H__
#define __CALLWITHARG_INT_FNS_H__

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// Public interface
void add_target_string(char* target);
bool remove_target_string(char* target);
void add_target_num(target_ulong target);
bool remove_target_num(target_ulong target);
// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif
