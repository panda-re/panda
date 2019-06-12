typedef void target_pid_t;

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


// returns operating system introspection info for each process in an array
OsiProcs *get_processes(CPUState *env);

// gets the currently running process
OsiProc *get_current_process(CPUState *env);

// returns operating system introspection info for each kernel module currently loaded
OsiModules *get_modules(CPUState *env);

// returns operating system introspection info for each userspace loaded library in the specified process
// returns the same type as get_modules
OsiModules *get_libraries(CPUState *env, OsiProc *p);

// returns the current thread
OsiThread *get_current_thread(CPUState *env);

// Free memory allocated by other library functions
void free_osiproc(OsiProc *p);
void free_osiprocs(OsiProcs *ps);
void free_osimodules(OsiModules *ms);
void free_osithread(OsiThread *t);
