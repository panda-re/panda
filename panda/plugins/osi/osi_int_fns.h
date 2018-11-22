#pragma once

// returns minimal handles for processes in an array
GArray *get_process_handles(CPUState *env);

// returns the current thread
OsiThread *get_current_thread(CPUState *env);

// returns information about the modules loaded by the guest OS kernel
GArray *get_modules(CPUState *env);

// returns information about the libraries loaded by a guest OS process
GArray *get_libraries(CPUState *env, OsiProc *p);

// returns operating system introspection info for each process in an array
GArray *get_processes(CPUState *env);

// gets the currently running process
OsiProc *get_current_process(CPUState *env);

// gets the process pointed to by task
OsiProc *get_process(CPUState *env, const OsiProcHandle *h);

