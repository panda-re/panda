// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

typedef struct {} VolatilityEnum;
typedef struct {} VolatilityBaseType;
typedef struct {} VolatilitySymbol;
typedef struct {} VolatilityStruct;


/**
 * Max length of process command (`comm` field in task_struct)
 */
#define TASK_COMM_LEN 16

/**
 * # Structure
 * `CosiFiles` holds a `Vec` of `CosiFile`s representing all open files for some process
 *     `files` is a `Vec` of `CosiFile`s representing the open files of a process
 * # Functions
 * `get_file_from_fd` returns the `CosiFile` with the given file descriptor from `files`
 * `get_current_cosifiles` returns a `CosiFiles` representing all open `file`s of the current process
 * `new` returns a `CosiFiles` representing all open `file`s associated with a `files_struct` at a given pointer
 */
typedef struct CosiFiles CosiFiles;

typedef struct String String;

typedef struct Vec_CosiModule Vec_CosiModule;

typedef struct Vec_CosiProc Vec_CosiProc;

typedef struct Path {
  target_ptr_t dentry;
  target_ptr_t mnt;
} Path;

typedef struct File {
  struct Path f_path;
  target_ptr_t f_pos;
} File;

/**
 * # Structure
 * `CosiFile` bundles useful data and metadata about `file`s
 *     `addr` is a pointer to the underlying  `file` structure
 *     `file_struct` is the underlying `file` read from memory
 *     `name` is the name of the file on disk associated with the `file`
 *     `fd` is the file descriptor associated with this `file` in the `files_struct` that keeps track of it
 * # Functions
 * `new` returns a `CosiFile` representing the `file` pointed to by a given pointer
 */
typedef struct CosiFile {
  /**
   * `addr` is a pointer to the underlying  `file` structure
   */
  target_ptr_t addr;
  /**
   * `file_struct` is the underlying `file` read from memory
   */
  struct File file_struct;
  /**
   * `name` is the name of the file on disk associated with the `file`
   */
  struct String *name;
  /**
   * `fd` is the file descriptor associated with this `file` in the `files_struct` that keeps track of it
   */
  uint32_t fd;
} CosiFile;

typedef struct ListHead {
  target_ptr_t next;
  target_ptr_t prev;
} ListHead;

typedef struct TaskStruct {
  struct ListHead tasks;
  uint32_t pid;
  uint32_t tgid;
  target_ptr_t group_leader;
  target_ptr_t thread_group;
  target_ptr_t real_parent;
  target_ptr_t parent;
  target_ptr_t mm;
  target_ptr_t stack;
  target_ptr_t real_cred;
  target_ptr_t cred;
  uint8_t comm[TASK_COMM_LEN];
  target_ptr_t files;
  target_ptr_t start_time;
  struct ListHead children;
  struct ListHead sibling;
} TaskStruct;

typedef struct MmStruct {
  uint32_t pgd;
  target_ptr_t arg_start;
  target_ptr_t start_brk;
  target_ptr_t brk;
  target_ptr_t start_stack;
  target_ptr_t mmap;
} MmStruct;

/**
 * # Structure
 * `CosiProc` bundles up useful data and metadata about `task_struct`s.
 *     `addr`  is a pointer to the underlying task_struct
 *     `task`  is the task_struct we read from the memory
 *     `name`  is the name of the process
 *     `ppid`  is the pid of the parent task_struct
 *     `mm`    is the mm_struct pointed to by task.mm, read from memory
 *     `asid`  is the asid of the process
 *     `taskd` is task.group_leader
 *
 *  # Functions
 * `get_next_process` walks task.tasks to find the next process in the process list and returns it as a CosiProc
 * `get_prev_process` walks task.tasks backwards to find the previous process in the process list and returns it as a CosiProc
 * `get_next_child` returns a CosiProc representaion of the process reffered to by task.children.next
 * `get_next_sibling` returns a CosiProc representation of the process reffered to by task.sibling.next
 * `get_init_cosiproc` returns a CosiProc representation of the process pointed to by the init_task symbol
 * `get_current_cosiproc` returns a CosiProc representation of the current process
 * `new` returns a CosiProc representation of a task_struct, given a pointer to that task_struct
 * `get_mappings` returns a CosiMappings representation of modules loaded in process represented by the CosiProc calling this function
 */
typedef struct CosiProc {
  /**
   * `addr` is a pointer to the underlying task_struct
   */
  target_ptr_t addr;
  /**
   * `task` is the task_struct we read from the memory
   */
  struct TaskStruct task;
  /**
   * `name` is the name of the process
   */
  struct String *name;
  /**
   * `ppid` is the pid of the parent task_struct
   */
  uint32_t ppid;
  /**
   * `mm` is the mm_struct pointed to by task.mm, read from memory
   */
  struct MmStruct *mm;
  /**
   * `asid`  is the asid of the process
   */
  uint32_t asid;
  /**
   * `taskd` is task.group_leader
   */
  target_ptr_t taskd;
} CosiProc;

/**
 * # Structure
 * `CosiThread` bundles up useful information about `thread_struct`s
 *     `tid` is the pid of the owning process
 *     `pid` is the thread group id of the owning process
 * # Functions
 * `get_current_cosithread` returns a CosiThread representation of the current process
 */
typedef struct CosiThread {
  /**
   * `tid` is the pid of the owning process
   */
  uint32_t tid;
  /**
   * `pid` is the thread group id of the owning process
   */
  uint32_t pid;
} CosiThread;

/**
 * # Structure
 * `CosiMappings` holds a `Vec` of `CosiModule`s representing all mapped memory regions for a process
 *     `modules` is a `Vec` of `CosiModule`s which each represent a mapped memory region for a process
 * # Functions
 * `new` returns a `CosiMappings` containing `CosiModule`s for all modules discoverable by traversing the `vm_next` linked list of a `vm_area_struct` at the given address
 */
typedef struct CosiMappings {
  /**
   * `modules` is a `Vec` of `CosiModule`s which each represent a mapped memory region for a process
   */
  struct Vec_CosiModule *modules;
} CosiMappings;

typedef struct VmAreaStruct {
  target_ptr_t vm_mm;
  target_ptr_t vm_start;
  target_ptr_t vm_end;
  target_ptr_t vm_next;
  target_ptr_t vm_file;
  target_ptr_t vm_flags;
} VmAreaStruct;

/**
 * # Structure
 * `CosiModule` bundles data and metadata associated with a `vm_area_struct`
 *     `modd` is a pointer to the underlying `vm_area_struct`
 *     `base` is `vm_area_struct.vm_start`
 *     `size` is `vm_area_struct.vm_end` - `vm_area_struct.vm_start`
 *     `vma` is the underlying `vm_area_struct` read from memory
 *     `file` is the path to the file backing the memory region
 *     `name` is the name of the file backing the memory region
 * # Functions
 * `new` returns a `CosiModule` representing the `vm_area_struct` at the given address
 */
typedef struct CosiModule {
  /**
   * `modd` is a pointer to the underlying `vm_area_struct`
   */
  target_ptr_t modd;
  /**
   * `base` is `vm_area_struct.vm_start`
   */
  target_ptr_t base;
  /**
   * `size` is `vm_area_struct.vm_end` - `vm_area_struct.vm_start`
   */
  target_ptr_t size;
  /**
   * `vma` is the underlying `vm_area_struct` read from memory
   */
  struct VmAreaStruct vma;
  /**
   * `file` is the path to the file backing the memory region
   */
  struct String *file;
  /**
   * `name` is the name of the file backing the memory region
   */
  struct String *name;
} CosiModule;

/**
 * Get the KASLR offset of the system, calculating and caching it if it has not already
 * been found. For systems without KASLR this will be 0.
 */
target_ptr_t kaslr_offset(CPUState *cpu);

/**
 * Get a reference to an opaque object for accessing information about a given enum
 * based on the volatility symbols currently loaded by OSI2
 */
const VolatilityEnum *enum_from_name(const char *name);

/**
 * Get a reference to an opaque object for accessing information about a given base type
 * from the volatility symbols currently loaded by OSI2
 */
const VolatilityBaseType *base_type_from_name(const char *name);

/**
 * Get a reference to an opaque object for accessing information about a given symbol
 * present in the volatility symbols currently loaded by OSI2
 */
const VolatilitySymbol *symbol_from_name(const char *name);

/**
 * Get a reference to an opaque object for accessing information about a given type
 * present in the volatility symbols currently loaded by OSI2
 */
const VolatilityStruct *type_from_name(const char *name);

/**
 * Get the address from a given symbol, accounting for KASLR
 */
target_ptr_t addr_of_symbol(const VolatilitySymbol *symbol);

/**
 * Get the raw value from a given symbol (unlike `addr_of_symbol` this does not account
 * for KASLR)
 */
target_ptr_t value_of_symbol(const VolatilitySymbol *symbol);

/**
 * Gets the name of the symbol as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_symbol(const VolatilitySymbol *symbol);

/**
 * Gets the name of the struct as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_struct(const VolatilityStruct *ty);

/**
 * Gets the name of the nth field in alphabetical order, returning null past the end
 */
char *get_field_by_index(const VolatilityStruct *ty, uintptr_t index);

/**
 * Gets the name of the enum as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_enum(const VolatilityEnum *ty);

/**
 * Gets the name of the base type as a C-compatible string, or null if the symbol cannot
 * be found. Must be freed via `free_cosi_str`.
 */
char *name_of_base_type(const VolatilityBaseType *ty);

/**
 * Gets the size of the base type in bytes
 */
target_ptr_t size_of_base_type(const VolatilityBaseType *ty);

/**
 * Check if an integral base type is signed
 */
bool is_base_type_signed(const VolatilityBaseType *ty);

/**
 * Get the raw value of a symbol, not accounting for aslr
 */
target_ptr_t symbol_value_from_name(const char *name);

/**
 * Given a symbol name, get the address of the symbol accounting for kaslr
 */
target_ptr_t symbol_addr_from_name(const char *name);

/**
 * Get the offset of a given field within a struct in bytes
 */
target_long offset_of_field(const VolatilityStruct *vol_struct, const char *name);

/**
 * Get the name of a given field as a string
 *
 * Must be freed using `free_cosi_str`
 */
char *type_of_field(const VolatilityStruct *vol_struct, const char *name);

/**
 * Get the size in bytes of a specific struct type
 */
target_ulong size_of_struct(const VolatilityStruct *vol_struct);

/**
 * Get the CPU offset for the currently executing CPU
 */
target_ulong current_cpu_offset(CPUState *cpu);

/**
 * Free a string allocated by cosi
 */
void free_cosi_str(char *string);

/**
 * Get the information for files available to the current process.
 *
 * Must be freed using `free_cosi_files`.
 */
struct CosiFiles *get_current_files(CPUState *cpu);

/**
 * Get the number of files in a given CosiFiles
 */
uintptr_t cosi_files_len(const struct CosiFiles *files);

/**
 * From a given CosiFiles get a specific file by index if it exists
 */
const struct CosiFile *cosi_files_get(const struct CosiFiles *files, uintptr_t index);

/**
 * Get a reference to a file from the file descriptor if it exists
 */
const struct CosiFile *cosi_files_file_from_fd(const struct CosiFiles *files, uint32_t fd);

/**
 * frees a CosiFiles struct
 */
void free_cosi_files(struct CosiFiles *files);

/**
 * Get the name of a given CosiFile
 *
 * Must be freed using `free_cosi_str`
 */
char *cosi_file_name(const struct CosiFile *file);

/**
 * Gets a reference to the current process which can be freed with `free_process`
 */
struct CosiProc *get_current_cosiproc(CPUState *cpu);

/**
 * Free an allocated reference to a process
 */
void free_process(struct CosiProc *proc);

/**
 * Get the name of a process from a reference to it as a C string. Must be freed using
 * the `free_cosi_str` function.
 */
char *cosi_proc_name(const struct CosiProc *proc);

/**
 * Gets the files accessible to the given process
 *
 * Must be freed via `free_cosi_files`
 */
struct CosiFiles *cosi_proc_files(const struct CosiProc *proc);

/**
 * Get the current thread, must be freed using `free_thread`
 */
struct CosiThread *get_current_cosithread(CPUState *cpu);

/**
 * Free an allocated reference to a thread
 */
void free_thread(struct CosiThread *thread);

/**
 * Gets a list of the current processes. Must be freed with `cosi_free_proc_list`
 */
struct Vec_CosiProc *cosi_get_proc_list(CPUState *cpu);

/**
 * Get a reference to an individual process in a cosi proc list
 */
const struct CosiProc *cosi_proc_list_get(const struct Vec_CosiProc *list, uintptr_t index);

/**
 * Get the length of a cosi proc list
 */
uintptr_t cosi_proc_list_len(const struct Vec_CosiProc *list);

/**
 * Free a cosi proc list
 */
void cosi_free_proc_list(struct Vec_CosiProc *_list);

/**
 * Gets a list of the children of a given process. Must be freed using `cosi_free_proc_list`
 */
struct Vec_CosiProc *cosi_proc_children(CPUState *cpu, const struct CosiProc *proc);

/**
 * Get a list of the memory mappings for the given process
 */
struct CosiMappings *cosi_proc_get_mappings(CPUState *cpu, const struct CosiProc *proc);

/**
 * Get the module behind the index of a CosiMappings
 */
const struct CosiModule *cosi_mappings_get(const struct CosiMappings *list, uintptr_t index);

/**
 * Get the number of modules in the CosiMappings
 */
uintptr_t cosi_mappings_len(const struct CosiMappings *list);

/**
 * Free the CosiMappings
 */
void cosi_free_mappings(struct CosiMappings *_mappings);

/**
 * Get the name of a module from a reference to it as a C string. Must be freed using
 * the `free_cosi_str` function.
 */
char *cosi_module_name(const struct CosiModule *module);

/**
 * Get the file path of a module from a reference to it as a C string. Must be freed using
 * the `free_cosi_str` function.
 */
char *cosi_module_file(const struct CosiModule *module);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
