#pragma once

typedef void (*on_get_processes_t)(CPUState *, GArray **);
typedef void (*on_get_process_handles_t)(CPUState *, GArray **);
typedef void (*on_get_current_process_t)(CPUState *, OsiProc **);
typedef void (*on_get_current_process_handle_t)(CPUState *, OsiProcHandle **);
typedef void (*on_get_process_t)(CPUState *, const OsiProcHandle *, OsiProc **);
typedef void (*on_get_modules_t)(CPUState *, GArray **);
typedef void (*on_get_mappings_t)(CPUState *, OsiProc *, GArray**);
typedef void (*on_get_current_thread_t)(CPUState *, OsiThread **);

typedef void (*on_get_process_pid_t)(CPUState *, const OsiProcHandle *, target_pid_t *);
typedef void (*on_get_process_ppid_t)(CPUState *, const OsiProcHandle *, target_pid_t *);

typedef void (*on_task_change_t)(CPUState *);
