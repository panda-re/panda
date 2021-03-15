/*!
 * @file osi_types.h
 * @brief Base data types for PANDA OSI.
 */
#pragma once
#include <gmodule.h>
#include "panda/types.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.


/**
 * @brief Minimal handle for a process. Contains a unique identifier \p asid
 * and a task descriptor pointer \p taskd that can be used to retrieve the full
 * details of the process.
 */
typedef struct osi_proc_handle_struct {
    target_ptr_t taskd;
    target_ptr_t asid;
} OsiProcHandle;

/**
 * @brief Minimal information about a process thread.
 * Address space and open resources are shared between threads
 * of the same process. This information is stored in OsiProc.
 */
typedef struct osi_thread_struct {
    target_pid_t pid;
    target_pid_t tid;
} OsiThread;

/**
 * @brief Represents a page in the address space of a process.
 *
 * @note This has not been implemented/used so far.
 */
typedef struct osi_page_struct {
    target_ptr_t start;
    target_ulong len;
} OsiPage;

/**
 * @brief Represents information about a guest OS module (kernel module
 * or shared library).
 */
typedef struct osi_module_struct {
    target_ptr_t modd;
    target_ptr_t base;
    target_ptr_t size;
    char *file;
    char *name;
} OsiModule;

/**
 * @brief Detailed information for a process.
 */
typedef struct osi_proc_struct {
    target_ptr_t taskd;
    target_ptr_t asid;
    target_pid_t pid;
    target_pid_t ppid;
    char *name;
    OsiPage *pages;
    uint64_t create_time;
} OsiProc;
// END_PYPANDA_NEEDS_THIS -- do not delete this comment!


/* ******************************************************************
 * Helper functions for freeing/copying osi structs.
 ******************************************************************* */

/**
 * @brief Dummy function for freeing contents of OsiProcHandle.
 * Meant to be passed to g_array_set_clear_func().
 * Defining a NULL function pointer rather than an an empty function
 * avoids unneeded calls during g_array_free().
 */
static void UNUSED((*free_osiprochandle_contents)(OsiProcHandle *)) = NULL;

/**
 * @brief Frees an OsiProcHandle struct and its contents.
 * To be used for freeing standalone OsiProcHandle structs.
 */
void free_osiprochandle(OsiProcHandle *h);

/**
 * @brief Dummy function for freeing contents of OsiThread.
 * Meant to be passed to g_array_set_clear_func().
 * Defining a NULL function pointer rather than an an empty function
 * avoids unneeded calls during g_array_free().
 */
static void UNUSED((*free_osithread_contents)(OsiThread *)) = NULL;

/**
 * @brief Frees an OsiThread struct and its contents.
 * To be used for freeing standalone OsiThread structs.
 */
void free_osithread(OsiThread *t);

/**
 * @brief Dummy function for freeing contents of OsiPage.
 * Meant to be passed to g_array_set_clear_func().
 * Defining a NULL function pointer rather than an an empty function
 * avoids unneeded calls during g_array_free().
 */
static void UNUSED((*free_osipage_contents)(OsiPage *)) = NULL;

/* vim:set tabstop=4 softtabstop=4 expandtab: */
