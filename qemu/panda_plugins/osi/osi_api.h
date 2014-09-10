


typedef struct osi_page_struct {
    target_ulong start;
    target_ulong len;
}


typedef struct osi_proc_struct {
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


void struct osi_modules_struct {
    uint32_t num;
    OsiModule *module;
} OsiModules;



// returns operating system introspection info for each process in an array
OsiProcs *get_processes(typedef);



// returns operating system introspection info for each kernel module currently loaded
OsiModules *get_modules(void);
