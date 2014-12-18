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

#endif
