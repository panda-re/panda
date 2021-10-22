#ifndef __HOOKS2_PPP_H
#define __HOOKS2_PPP_H
// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// Hook functions must be of this type
PPP_CB_TYPEDEF(bool,hooks2_func,CPUState *, TranslationBlock *, void *);


PPP_CB_TYPEDEF(void,on_process_start,CPUState *cpu,const char *procname,target_ulong asid,target_pid_t pid);

PPP_CB_TYPEDEF(void,on_process_end,CPUState *cpu,const char *procname,target_ulong asid,target_pid_t pid);

PPP_CB_TYPEDEF(void,on_thread_start,CPUState* cpu,const char *procname,target_ulong asid,target_pid_t pid,target_pid_t tid);

PPP_CB_TYPEDEF(void,on_thread_end,CPUState* cpu,const char *procname,target_ulong asid,target_pid_t pid,target_pid_t tid);

PPP_CB_TYPEDEF(void,on_mmap_updated,CPUState* cpu,const char *libname,target_ulong base,target_ulong size);


PPP_CB_TYPEDEF(int,_add_hooks2,hooks2_func_t hook,void *cb_data,bool is_kernel,const char *procname,const char *libname,target_ulong trace_start,target_ulong trace_stop,target_ulong range_begin,target_ulong range_end);

PPP_CB_TYPEDEF(void,_enable_hooks2,int id);
PPP_CB_TYPEDEF(void,_disable_hooks2,int id);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif
