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

typedef struct String String;

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
} TaskStruct;

typedef struct MmStruct {
  uint32_t pgd;
  target_ptr_t arg_start;
  target_ptr_t start_brk;
  target_ptr_t brk;
  target_ptr_t start_stack;
  target_ptr_t mmap;
} MmStruct;

typedef struct CosiProc {
  target_ptr_t addr;
  struct TaskStruct task;
  struct String name;
  uint32_t ppid;
  struct MmStruct mm;
  uint32_t asid;
  target_ptr_t taskd;
} CosiProc;

typedef struct CosiThread {
  uint32_t tid;
  uint32_t pid;
} CosiThread;

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

bool is_base_type_signed(const VolatilityBaseType *ty);

target_ptr_t symbol_value_from_name(const char *name);

target_ptr_t symbol_addr_from_name(const char *name);

target_long offset_of_field(const VolatilityStruct *vol_struct, const char *name);

char *type_of_field(const VolatilityStruct *vol_struct, const char *name);

target_ulong size_of_struct(const VolatilityStruct *vol_struct);

target_ulong current_cpu_offset(CPUState *cpu);

void free_cosi_str(char *string);

/**
 * Gets a reference to the current process which can be freed with `free_process`
 */
struct CosiProc *get_current_process(CPUState *cpu);

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
 * Get the current thread, must be freed using `free_thread`
 */
struct CosiThread *get_current_thread(CPUState *cpu);

/**
 * Free an allocated reference to a thread
 */
void free_thread(struct CosiThread *thread);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
