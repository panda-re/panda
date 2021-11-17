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
PPP_CB_TYPEDEF(void,on_get_modules,CPUState *, GArray **);
PPP_CB_TYPEDEF(void,on_get_mappings,CPUState *, OsiProc *, GArray**);
PPP_CB_TYPEDEF(void,on_get_current_thread,CPUState *, OsiThread **);

PPP_CB_TYPEDEF(void,on_get_process_pid,CPUState *, const OsiProcHandle *, target_pid_t *);
PPP_CB_TYPEDEF(void,on_get_process_ppid,CPUState *, const OsiProcHandle *, target_pid_t *);

PPP_CB_TYPEDEF(void,on_task_change,CPUState *);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif
