#ifndef __DYNAMIC_SYMBOLS_INT_FNS_H__
#define __DYNAMIC_SYMBOLS_INT_FNS_H__

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

target_ulong resolve_symbol(target_ulong asid, char* section_name, char* symbol);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif
