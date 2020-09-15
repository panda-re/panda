#ifndef __HOOKS2_PPP_H
#define __HOOKS2_PPP_H
// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// Hook functions must be of this type
typedef bool (*hooks2_func_t)(CPUState *, TranslationBlock *, void *);


typedef void (*on_process_start_t)(CPUState *cpu,const char *procname,target_ulong asid,target_pid_t pid);

typedef void (*on_process_end_t)(CPUState *cpu,const char *procname,target_ulong asid,target_pid_t pid);

typedef void (*on_thread_start_t)(CPUState* cpu,const char *procname,target_ulong asid,target_pid_t pid,target_pid_t tid);

typedef void (*on_thread_end_t)(CPUState* cpu,const char *procname,target_ulong asid,target_pid_t pid,target_pid_t tid);

typedef void (*on_mmap_updated_t)(CPUState* cpu,const char *libname,target_ulong base,target_ulong size);


typedef int (*_add_hooks2_t)(hooks2_func_t hook,void *cb_data,bool is_kernel,const char *procname,const char *libname,target_ulong trace_start,target_ulong trace_stop,target_ulong range_begin,target_ulong range_end);

typedef void (*_enable_hooks2_t)(int id);
typedef void (*_disable_hooks2_t)(int id);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif