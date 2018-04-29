#ifndef __CALLSTACK_INSTR_INT_FNS_H__
#define __CALLSTACK_INSTR_INT_FNS_H__

// Public interface

// Get up to n callers from the given address space at this moment
// Callers are returned in callers[], most recent first
uint32_t get_callers(target_ulong *callers, uint32_t n, CPUState *cpu);

// Get up to n functions from the given address space at this moment
// Functions are returned in functions[], most recent first
uint32_t get_functions(target_ulong *functions, uint32_t n, CPUState *cpu);

// Get the current program point: (Caller, PC, ASID)
// This isn't quite the right place for it, but since it's awkward
// right now to have a "utilities" library, this will have to do
void get_prog_point(CPUState *cpu, prog_point *p);

// create pandalog message for callstack info
Panda__CallStack *pandalog_callstack_create(void);

// free that data structure
void pandalog_callstack_free(Panda__CallStack *cs);

#endif
