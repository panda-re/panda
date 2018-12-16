


/**
 * Object:
 *
 * The base for all objects.  The first member of this object is a pointer to
 * a #ObjectClass.  Since C guarantees that the first member of a structure
 * always begins at byte 0 of that structure, as long as any sub-object places
 * its parent as the first member, we can cast directly to a #Object.
 *
 * As a result, #Object contains a reference to the objects type as its
 * first member.  This allows identification of the real type of the object at
 * run time.
 */
struct Object
{
    /*< private >*/
    void* klass; //ObjectClass *klass;
    void* free; //ObjectFree *free;
    void* properties; //GHashTable *properties;
    uint32_t ref;
    void* parent;
};


/**
 * DeviceState:
 * @realized: Indicates whether the device has been fully constructed.
 *
 * This structure should not be accessed directly.  We declare it here
 * so that it can be embedded in individual device state structures.
 */
struct DeviceState {
    /*< private >*/
    struct Object parent_obj;
    /*< public >*/
    
    const char *id;
    bool realized;
    bool pending_deleted_event;
    void* opts; //QemuOpts *opts;
    int hotplugged;
    void* parent_bus; //BusState *parent_bus;
    void* gpios; //QLIST_HEAD(, NamedGPIOList) gpios;
    void* child_bus; //QLIST_HEAD(, BusState) child_bus;
    int num_child_bus;
    int instance_id_alias;
    int alias_required_for_version;
};

typedef struct {
  int __flags[8];			/* XXX - long might give better alignment */
  long __mask;			/* must have size >= sizeof(sigset_t) */
//#if (_SETJMP_SAVES_REGS == 0)
// _PROTOTYPE(void (*__pc),(void));	/* program counter */
//  void *__sp;			/* stack pointer */
//  void *__lb;			/* local base (ACKspeak for frame pointer) */
//#else
  void *__regs[16];		/* size is machine dependent */
//#endif
} jmp_buf[1];
typedef jmp_buf sigjmp_buf;

struct QemuMutex {
	pthread_mutex_t lock;
};

typedef struct icount_decr_u16 {
    uint16_t low;
    uint16_t high;
} icount_decr_u16;
typedef struct QemuMutex QemuMutex;
typedef uint64_t vaddr;
#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE 4096 // 1<<12
/**
 * CPUState:
 * @cpu_index: CPU index (informative).
 * @nr_cores: Number of cores within this CPU package.
 * @nr_threads: Number of threads within this CPU.
 * @numa_node: NUMA node this CPU is belonging to.
 * @host_tid: Host thread ID.
 * @running: #true if CPU is currently running (lockless).
 * @has_waiter: #true if a CPU is currently waiting for the cpu_exec_end;
 * valid under cpu_list_lock.
 * @created: Indicates whether the CPU thread has been successfully created.
 * @interrupt_request: Indicates a pending interrupt request.
 * @halted: Nonzero if the CPU is in suspended state.
 * @stop: Indicates a pending stop request.
 * @stopped: Indicates the CPU has been artificially stopped.
 * @unplug: Indicates a pending CPU unplug request.
 * @crash_occurred: Indicates the OS reported a crash (panic) for this CPU
 * @tcg_exit_req: Set to force TCG to stop executing linked TBs for this
 *           CPU and return to its top level loop.
 * @singlestep_enabled: Flags for single-stepping.
 * @icount_extra: Instructions until next timer event.
 * @icount_decr: Number of cycles left, with interrupt flag in high bit.
 * This allows a single read-compare-cbranch-write sequence to test
 * for both decrementer underflow and exceptions.
 * @can_do_io: Nonzero if memory-mapped IO is safe. Deterministic execution
 * requires that IO only be performed on the last instruction of a TB
 * so that interrupts take effect immediately.
 * @cpu_ases: Pointer to array of CPUAddressSpaces (which define the
 *            AddressSpaces this CPU has)
 * @num_ases: number of CPUAddressSpaces in @cpu_ases
 * @as: Pointer to the first AddressSpace, for the convenience of targets which
 *      only have a single AddressSpace
 * @env_ptr: Pointer to subclass-specific CPUArchState field.
 * @gdb_regs: Additional GDB registers.
 * @gdb_num_regs: Number of total registers accessible to GDB.
 * @gdb_num_g_regs: Number of registers in GDB 'g' packets.
 * @next_cpu: Next CPU sharing TB cache.
 * @opaque: User data.
 * @mem_io_pc: Host Program Counter at which the memory was accessed.
 * @mem_io_vaddr: Target virtual address at which the memory was accessed.
 * @kvm_fd: vCPU file descriptor for KVM.
 * @work_mutex: Lock to prevent multiple access to queued_work_*.
 * @queued_work_first: First asynchronous work pending.
 * @trace_dstate: Dynamic tracing state of events for this vCPU (bitmask).
 *
 * State of one CPU core or thread.
 */
	struct CPUState {
	    /*< private >*/
//	    struct DeviceState parent_obj; //DeviceState parent_obj;
	    /*< public >*/
/*
	    int nr_cores;
	    int nr_threads;
	    int numa_node;

	    void* thread; //struct QemuThread *thread;
//	#ifdef _WIN32
//	    HANDLE hThread;
//	#endif
	    int thread_id;
	    uint32_t host_tid;
	    bool running, has_waiter;
	    struct QemuCond *halt_cond;
	    bool thread_kicked;
	    bool created;
	    bool stop;
	    bool stopped;
	    bool unplug;
	    bool crash_occurred;
	    bool exit_request;
	    uint32_t interrupt_request;
	    int singlestep_enabled;
	    int64_t icount_extra;
	    sigjmp_buf jmp_env;

	    QemuMutex work_mutex;
	    struct qemu_work_item *queued_work_first, *queued_work_last;

	    void* cpu_ases; //CPUAddressSpace *cpu_ases;
	    int num_ases;
	    void* as; //AddressSpace *as;
	    void* memory; //MemoryRegion *memory;
*/
		char values[472];
	    CPUX86State *env_ptr; // CPUArchState *env_ptr; /* CPUArchState */
		char values2[32924];
		
	    /* Writes protected by tb_lock, reads not thread-safe  */ 
/*
	    void* tb_jmp_cache[TB_JMP_CACHE_SIZE]; //struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];
	    struct GDBRegisterState *gdb_regs;
	    int gdb_num_regs;
	    int gdb_num_g_regs;
	    void* node; //QTAILQ_ENTRY(CPUState) node;

*/	    /* ice debug support */
/*	    void* breakpoints; //QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;

	    void* watchpoints; //QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;
	    void* watchpoint_hit; //CPUWatchpoint *watchpoint_hit;
	    bool watchpoints_disabled;

	    void *opaque;
*/
	    /* In order to avoid passing too many arguments to the MMIO helpers,
	     * we store some rarely used information in the CPU context.
	     */
/*	    uintptr_t mem_io_pc;
	    vaddr mem_io_vaddr;

	    int kvm_fd;
	    bool kvm_vcpu_dirty;
	    struct KVMState *kvm_state;
	    struct kvm_run *kvm_run;

*/	    /*
	     * Used for events with 'vcpu' and *without* the 'disabled' properties.
	     * Dynamically allocated based on bitmap requried to hold up to
	     * trace_get_vcpu_event_count() entries.
	     */
/*	    unsigned long *trace_dstate;

*/	    /* TODO Move common fields from CPUArchState here. */
//	    int cpu_index; /* used by alpha TCG */
//	    uint32_t halted; /* used by alpha, cris, ppc TCG */
//	    union {
//		uint32_t u32;
//		icount_decr_u16 u16;
//	    } icount_decr;
//	    uint32_t can_do_io;
//	    int32_t exception_index; /* used by m68k TCG */
	    uint64_t rr_guest_instr_count;
	    uint64_t panda_guest_pc;

	    // Used for rr reverse debugging
//	    uint8_t reverse_flags;
//	    uint64_t last_gdb_instr; // Instruction count from which we last sent a GDB command
//	    uint64_t last_bp_hit_instr; // Last bp observed during this checkpoint run
//	    uint64_t temp_rr_bp_instr; // Saved bp. Used by rstep/rcont, which disables bp to move forward, then restores on next tb in cpu-exec.c

	    /* Used to keep track of an outstanding cpu throttle thread for migration
	     * autoconverge
	     */
//	    bool throttle_thread_scheduled;

	    /* Note that this is accessed at the start of every TB via a negative
	       offset from AREG0.  Leave this field at the end so as to make the
	       (absolute value) offset as small as possible.  This reduces code
	       size, especially for hosts without large memory offsets.  */
//	    uint32_t tcg_exit_req;

//	    bool hax_vcpu_dirty;
//	    void* hax_vcpu; //struct hax_vcpu_state *hax_vcpu;
	};
typedef struct CPUState CPUState;

typedef uint64_t ram_addr_t;
typedef ram_addr_t tb_page_addr_t;
struct TranslationBlock {
    target_ulong pc;   /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint32_t flags; /* flags defining in which context the code was generated */
    uint16_t size;      /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    uint16_t icount;
    uint32_t cflags;    /* compile flags */
#define CF_COUNT_MASK  0x7fff
#define CF_LAST_IO     0x8000 /* Last insn may be an IO access.  */
#define CF_NOCACHE     0x10000 /* To be freed after execution */
#define CF_USE_ICOUNT  0x20000
#define CF_IGNORE_ICOUNT 0x40000 /* Do not generate icount code */

    uint16_t invalid;

    void *tc_ptr;    /* pointer to the translated code */
    uint8_t *tc_search;  /* pointer to search data */
    /* original tb when cflags has CF_NOCACHE */
    struct TranslationBlock *orig_tb;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    struct TranslationBlock *page_next[2];
    tb_page_addr_t page_addr[2];

    /* The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continue its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */
#define TB_JMP_RESET_OFFSET_INVALID 0xffff /* indicates no jump generated */
//#ifdef USE_DIRECT_JUMP
    uint16_t jmp_insn_offset[2]; /* offset of native jump instruction */
//#else
    uintptr_t jmp_target_addr[2]; /* target address for indirect jump */
//#endif
    /* Each TB has an assosiated circular list of TBs jumping to this one.
     * jmp_list_first points to the first TB jumping to this one.
     * jmp_list_next is used to point to the next TB in a list.
     * Since each TB can have two jumps, it can participate in two lists.
     * jmp_list_first and jmp_list_next are 4-byte aligned pointers to a
     * TranslationBlock structure, but the two least significant bits of
     * them are used to encode which data field of the pointed TB should
     * be used to traverse the list further from that TB:
     * 0 => jmp_list_next[0], 1 => jmp_list_next[1], 2 => jmp_list_first.
     * In other words, 0/1 tells which jump is used in the pointed TB,
     * and 2 means that this is a pointer back to the target TB of this list.
     */
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_list_first;

//#ifdef CONFIG_LLVM
    /* pointer to LLVM translated code */
    struct TCGLLVMContext *tcg_llvm_context;
//#ifdef __cplusplus
    void* llvm_function; //Function *llvm_function;
//#else
//    struct Function *llvm_function;
//#endif
    uint8_t *llvm_tc_ptr;
    uint8_t *llvm_tc_end;
    struct TranslationBlock* llvm_tb_next[2];
//#endif

};
typedef struct TranslationBlock TranslationBlock;
typedef target_ulong target_long;

struct MonitorDef {
	const char *name;
	int offset;
	target_long (*get_value)(void  *md, int val);
	int type;
};

typedef struct MonitorDef Monitor;
