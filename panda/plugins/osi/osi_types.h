/*!
 * @file osi_types.h
 * @brief Base data types for PANDA OSI.
 */
#pragma once
#include "panda/types.h"

typedef struct osi_page_struct {
    target_ptr_t start;
    target_ulong len;
} OsiPage;

typedef struct osi_proc_struct {
    target_ptr_t offset;
    char *name;
    target_ptr_t asid;
    OsiPage *pages;
    target_ptr_t pid;
    target_ptr_t ppid;
} OsiProc;

typedef struct osi_procs_struct {
    uint32_t num;
    uint32_t capacity;
    OsiProc *proc;
} OsiProcs;

typedef struct osi_module_struct {
    target_ptr_t offset;
    char *file;
    target_ptr_t base;
    target_ptr_t size;
    char *name;
} OsiModule;

typedef struct osi_modules_struct {
    uint32_t num;
    uint32_t capacity;
    OsiModule *module;
} OsiModules;

typedef struct osi_thread_struct {
    target_pid_t tid;
    target_pid_t pid;
} OsiThread;

/*
 * Generic inlines for handling OsiProc, OsiProcs structs.
 * It is left to the OS-specific modules to use them or not.
 */

/** @brief Frees an OsiProc struct. */
static inline void free_osiproc_g(OsiProc *p) {
    if (p == NULL) return;
    g_free(p->name);
    g_free(p);
    return;
}

/** @brief Frees an OsiProcs struct. */
static inline void free_osiprocs_g(OsiProcs *ps) {
    if (ps == NULL) return;
    for (uint32_t i = 0; i < ps->num; i++) {
        g_free(ps->proc[i].name);
    }
    g_free(ps->proc);
    g_free(ps);
    return;
}

static inline void free_osimodule_g(OsiModule *m) {
    g_free(m->file);
    g_free(m->name);
    g_free(m);
}

static inline void free_osithread_g(OsiThread *t) { g_free(t); }

/**
 * @brief Copies an OsiProc struct. Returns a pointer to the destination location.
 *
 * @note Members of `to` struct must have been freed to avoid memory leaks.
 */
static inline OsiProc *copy_osiproc_g(OsiProc *from, OsiProc *to) {
    if (from == NULL) return NULL;
    if (to == NULL) to = (OsiProc *)g_malloc0(sizeof(OsiProc));

    memcpy(to, from, sizeof(OsiProc));
    to->name = g_strdup(from->name);
    to->pages = NULL;  // OsiPage - TODO
    return to;
}

static inline OsiModule *copy_osimod_g(OsiModule *from, OsiModule *to) {
    if (from == NULL) return NULL;
    if (to == NULL) to = (OsiModule *)g_malloc0(sizeof(OsiModule));

    memcpy(to, from, sizeof(OsiModule));
    to->name = g_strdup(from->name);
    to->file = g_strdup(from->file);
    return to;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
