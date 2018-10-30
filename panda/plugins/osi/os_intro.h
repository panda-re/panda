#pragma once

typedef void (*on_get_processes_t)(CPUState *, OsiProcs **);
typedef void (*on_get_process_handles_t)(CPUState *, GArray **);
typedef void (*on_get_current_process_t)(CPUState *, OsiProc **);
typedef void (*on_get_process_t)(CPUState *, OsiProcHandle *, OsiProc **);
typedef void (*on_get_modules_t)(CPUState *, OsiModules **);
typedef void (*on_get_libraries_t)(CPUState *, OsiProc *, OsiModules**);
typedef void (*on_get_current_thread_t)(CPUState *, OsiThread **);
typedef void (*on_free_osiproc_t)(OsiProc *p);
typedef void (*on_free_osiprocs_t)(OsiProcs *ps);
typedef void (*on_free_osimodules_t)(OsiModules *ms);
typedef void (*on_free_osithread_t)(OsiThread *t);
#ifdef OSI_PROC_EVENTS
typedef void (*on_process_start_t)(CPUState *, OsiProc *);
typedef void (*on_process_end_t)(CPUState *, OsiProc *);
#endif

