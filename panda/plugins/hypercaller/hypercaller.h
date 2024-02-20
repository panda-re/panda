#ifndef __HYPERCALLER_H
#define __HYPERCALLER_H
// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

typedef void (*hypercall_t)(CPUState *cpu);
void register_hypercall(target_ulong magic, hypercall_t);
void unregister_hypercall(target_ulong magic);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif