#ifndef __OS_INTRO_H
#define __OS_INTRO_H

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

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

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

/**
 * @brief Frees an OsiPage struct and its contents.
 * To be used for freeing standalone OsiPage structs.
 */
void free_osipage(OsiPage *p);

/**
 * @brief Frees the contents of an OsiModule struct.
 * Meant to be passed to g_array_set_clear_func.
 */
//void free_osimodule_contents(OsiModule *m);
static inline void free_osimodule_contents(OsiModule *m) {
    if (m == NULL) return;
    g_free(m->file);
    g_free(m->name);
}

/**
 * @brief Frees an OsiModule struct and its contents.
 * To be used for freeing standalone OsiModule structs.
 */
void free_osimodule(OsiModule *m);

/**
 * @brief Frees the contents of an OsiProc struct.
 * Meant to be passed to g_array_set_clear_func.
 */
//void free_osiproc_contents(OsiProc *p);
static inline void free_osiproc_contents(OsiProc *p) {
    if (p == NULL) return;
    g_free(p->name);
    g_free(p->pages);
}

/**
 * @brief Frees an OsiProc struct and its contents.
 * To be used for freeing standalone OsiProc structs.
 */
//void free_osiproc(OsiProc *p);


/**
 * @brief Copies an OsiProcHandle struct.
 * Returns a pointer to the destination location.
 */
OsiProcHandle *copy_osiprochandle(OsiProcHandle *from, OsiProcHandle *to);

void free_osiproc(OsiProc *p);

/**
 * @brief Copies an OsiProc struct.
 * Returns a pointer to the destination location.
 */
OsiProc *copy_osiproc(OsiProc *from, OsiProc *to);

/**
 * @brief Copies an OsiModule struct.
 * Returns a pointer to the destination location.
 */
OsiModule *copy_osimod(OsiModule *from, OsiModule *to);

#endif
