#pragma once

typedef void (*on_get_processes_t)(CPUState *, GArray **);
typedef void (*on_get_process_handles_t)(CPUState *, GArray **);
typedef void (*on_get_current_process_t)(CPUState *, OsiProc **);
typedef void (*on_get_process_t)(CPUState *, const OsiProcHandle *, OsiProc **);
typedef void (*on_get_modules_t)(CPUState *, GArray **);
typedef void (*on_get_libraries_t)(CPUState *, OsiProc *, GArray**);
typedef void (*on_get_current_thread_t)(CPUState *, OsiThread **);
#ifdef OSI_PROC_EVENTS
typedef void (*on_process_start_t)(CPUState *, OsiProc *);
typedef void (*on_process_end_t)(CPUState *, OsiProc *);
#endif

