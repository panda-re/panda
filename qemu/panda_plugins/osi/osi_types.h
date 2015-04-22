#ifndef OSI_TYPES_H
#define OSI_TYPES_H

typedef struct osi_page_struct {
    target_ulong start;
    target_ulong len;
} OsiPage;

typedef struct osi_proc_struct {
    target_ulong offset;
    char *name;
    target_ulong asid;
    OsiPage *pages;
    target_ulong pid;
    target_ulong ppid;
} OsiProc;

typedef struct osi_procs_struct {
    uint32_t num;
    OsiProc *proc;
} OsiProcs;

typedef struct osi_module_struct {
    target_ulong offset;
    char *file;
    target_ulong base;
    target_ulong size;
    char *name;
} OsiModule;

typedef struct osi_modules_struct {
    uint32_t num;
    OsiModule *module;
} OsiModules;



/*
 * Generic inlines for handling OsiProc, OsiProcs structs.
 * It is left to the OS-specific modules to use them or not.
 */

/*! @brief Frees an OsiProc struct. */
static inline void free_osiproc_g(OsiProc *p) {
	if (p == NULL) return;
	g_free(p->name);
	g_free(p);
	return;
}

/*! @brief Frees an OsiProcs struct. */
static inline void free_osiprocs_g(OsiProcs *ps) {
	uint32_t i;
	if (ps == NULL) return;
	for (i=0; i< ps->num; i++) {
		g_free(ps->proc[i].name);
	}
	g_free(ps->proc);
	g_free(ps);
	return;
}

/*! @brief Copies an OsiProc struct. Returns a pointer to the destination location.
 *
 * @note Members of `to` struct must have been freed to avoid memory leaks.
 */
static inline OsiProc *copy_osiproc_g(OsiProc *from, OsiProc *to) {
	if (from == NULL) return NULL;
	if (to == NULL) to = (OsiProc *)g_malloc0(sizeof(OsiProc));

	memcpy(to, from, sizeof(OsiProc));
	to->name = g_strdup(from->name);
	to->pages = NULL; // OsiPage - TODO
	return to;
}
#endif
