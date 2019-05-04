typedef void target_pid_t;
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
    target_ptr_t pid;
    target_ptr_t ppid;
    char *name;
    OsiPage *pages;
} OsiProc;

