#ifndef __OSI_INT_FNS_H__
#define __OSI_INT_FNS_H__

// returns operating system introspection info for each process in an array
OsiProcs *get_processes(CPUState *env);

// gets the currently running process
OsiProc *get_current_process(CPUState *env);

// returns operating system introspection info for each kernel module currently loaded
OsiModules *get_modules(CPUState *env);

// returns operating system introspection info for each userspace loaded library in the specified process
// returns the same type as get_modules
OsiModules *get_libraries(CPUState *env, OsiProc *p);

// Free memory allocated by other library functions
void free_osiproc(OsiProc *p);
void free_osiprocs(OsiProcs *ps);
void free_osimodules(OsiModules *ms);

#endif
