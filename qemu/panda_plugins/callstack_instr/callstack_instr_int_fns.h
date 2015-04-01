#ifndef __CALLSTACK_INSTR_INT_FNS_H__
#define __CALLSTACK_INSTR_INT_FNS_H__

// Public interface

// Get up to n callers from the given address space at this moment
// Callers are returned in callers[], most recent first
int get_callers(target_ulong *callers, int n, CPUState *env);

// Get up to n functions from the given address space at this moment
// Functions are returned in functions[], most recent first
int get_functions(target_ulong *functions, int n, CPUState *env);

// Get the current program point: (Caller, PC, ASID)
// This isn't quite the right place for it, but since it's awkward
// right now to have a "utilities" library, this will have to do
void get_prog_point(CPUState *env, prog_point *p);

// writes callstack info to pandalog
void callstack_pandalog(void);

#endif
