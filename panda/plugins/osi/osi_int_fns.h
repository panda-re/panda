#pragma once

// returns operating system introspection info for each process in an array
GArray *get_processes(CPUState *env);

// returns minimal handles for processes in an array
GArray *get_process_handles(CPUState *env);

// gets the currently running process
OsiProc *get_current_process(CPUState *env);

// gets the process pointed to by task
OsiProc *get_process(CPUState *env, OsiProcHandle *h);

// returns operating system introspection info for each kernel module currently loaded
OsiModules *get_modules(CPUState *env);

// returns operating system introspection info for each userspace loaded library in the specified process
// returns the same type as get_modules
OsiModules *get_libraries(CPUState *env, OsiProc *p);

// returns the current thread
OsiThread *get_current_thread(CPUState *env);

