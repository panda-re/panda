#pragma once

#include <stdbool.h>

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// returns minimal handles for processes in an array
GArray *get_process_handles(CPUState *cpu);

// returns the current thread
OsiThread *get_current_thread(CPUState *cpu);

// returns information about the modules loaded by the guest OS kernel
GArray *get_modules(CPUState *cpu);

// returns information about the memory mappings of libraries loaded by a guest OS process
GArray *get_mappings(CPUState *cpu, OsiProc *p);

// returns process specific memory parameters (start_brk/brk)
// supported in osi_linux only
OsiProcMem *get_proc_mem(CPUState *cpu, const OsiProc *p);

// like get_mappings, but only return segments backed by files
// for wintrospection, this is the same as get_mappings
GArray *get_file_mappings(CPUState *cpu, OsiProc *p);

// like get_mappings, but only return heap segments
// supported in osi_linux only
GArray *get_heap_mappings(CPUState *cpu, OsiProc *p);

// like get_mappings, but only return stack segments
// supported in osi_linux only
GArray *get_stack_mappings(CPUState *cpu, OsiProc *p);

// like get_mappings, but only return "unknown" segments
// these can be additional heap areas, but could also be memory segments
// created by the running process that aren't backed by a file
// supported in osi_linux only
GArray *get_unknown_mappings(CPUState *cpu, OsiProc *p);

// get mapping that corresponds to virtual memory address addr
OsiModule *get_mapping_by_addr(CPUState *cpu, OsiProc *p, const target_ptr_t addr);

// get the base address for the mapping with the specified name
target_ptr_t get_mapping_base_address_by_name(CPUState *cpu, OsiProc *p, const char *name);

// returns true if a mapping exists whose name begins with prefix
bool has_mapping_prefix(CPUState *cpu, OsiProc *p, const char *prefix);

// returns operating system introspection info for each process in an array
GArray *get_processes(CPUState *cpu);

// gets the currently running process
OsiProc *get_current_process(CPUState *cpu);

OsiModule* get_one_module(GArray *osimodules, unsigned int idx);

OsiProc* get_one_proc(GArray *osiprocs, unsigned int idx);

void cleanup_garray(GArray *g);

// returns true if execution is currently within a dynamically-linked function, else false.
bool in_shared_object(CPUState *cpu, OsiProc *p);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

// gets the currently running process handle
OsiProcHandle *get_current_process_handle(CPUState *cpu);

// gets the process pointed to by the handle
OsiProc *get_process(CPUState *cpu, const OsiProcHandle *h);

// functions retrieving partial process information via an OsiProcHandle
target_pid_t get_process_pid(CPUState *cpu, const OsiProcHandle *h);
target_pid_t get_process_ppid(CPUState *cpu, const OsiProcHandle *h);

void notify_task_change(CPUState *cpu);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
