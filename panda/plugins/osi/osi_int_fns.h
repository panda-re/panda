#pragma once

// returns minimal handles for processes in an array
GArray *get_process_handles(CPUState *cpu);

// returns the current thread
OsiThread *get_current_thread(CPUState *cpu);

// returns information about the modules loaded by the guest OS kernel
GArray *get_modules(CPUState *cpu);

// returns information about the libraries loaded by a guest OS process
GArray *get_libraries(CPUState *cpu, OsiProc *p);

// returns operating system introspection info for each process in an array
GArray *get_processes(CPUState *cpu);

// gets the currently running process
OsiProc *get_current_process(CPUState *cpu);

// gets the currently running process handle
OsiProcHandle *get_current_process_handle(CPUState *cpu);

// gets the process pointed to by the handle
OsiProc *get_process(CPUState *cpu, const OsiProcHandle *h);

