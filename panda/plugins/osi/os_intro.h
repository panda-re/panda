#ifndef __OS_INTRO_H
#define __OS_INTRO_H

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

PPP_CB_TYPEDEF(void,on_get_processes,CPUState *, GArray **);
PPP_CB_TYPEDEF(void,on_get_process_handles,CPUState *, GArray **);
PPP_CB_TYPEDEF(void,on_get_current_process,CPUState *, OsiProc **);
PPP_CB_TYPEDEF(void,on_get_current_process_handle,CPUState *, OsiProcHandle **);
PPP_CB_TYPEDEF(void,on_get_process,CPUState *, const OsiProcHandle *, OsiProc **);
PPP_CB_TYPEDEF(void,on_get_proc_mem,CPUState *cpu, const OsiProc *p, OsiProcMem **);
PPP_CB_TYPEDEF(void,on_get_modules,CPUState *, GArray **);
PPP_CB_TYPEDEF(void,on_get_mappings,CPUState *, OsiProc *, GArray**);
PPP_CB_TYPEDEF(void,on_get_file_mappings,CPUState *, OsiProc *, GArray**);
PPP_CB_TYPEDEF(void,on_get_heap_mappings,CPUState *, OsiProc *, GArray**);
PPP_CB_TYPEDEF(void,on_get_stack_mappings,CPUState *, OsiProc *, GArray**);
PPP_CB_TYPEDEF(void,on_get_unknown_mappings,CPUState *, OsiProc *, GArray**);
PPP_CB_TYPEDEF(void,on_get_mapping_by_addr,CPUState *, OsiProc *, const target_ptr_t, OsiModule **);
PPP_CB_TYPEDEF(void,on_get_mapping_base_address_by_name,CPUState *, OsiProc *, const char *, target_ptr_t *);
PPP_CB_TYPEDEF(void,on_has_mapping_prefix,CPUState *, OsiProc *, const char *, bool *);
PPP_CB_TYPEDEF(void,on_get_current_thread,CPUState *, OsiThread **);

PPP_CB_TYPEDEF(void,on_get_process_pid,CPUState *, const OsiProcHandle *, target_pid_t *);
PPP_CB_TYPEDEF(void,on_get_process_ppid,CPUState *, const OsiProcHandle *, target_pid_t *);

PPP_CB_TYPEDEF(void,on_task_change,CPUState *);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif
