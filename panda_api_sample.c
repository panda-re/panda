// gcc -g  -o papi panda_api_sample.c ./build/i386-softmmu/libpanda-i386.so
#define CONFIG_SOFTMMU
#define PYPANDA

#include <stdint.h>
#define target_ulong uint32_t
#include "panda/types.h"
/**
 * CPUState:
 * @cpu_index: CPU index (informative).
 * @nr_cores: Number of cores within this CPU package.
 * @nr_threads: Number of threads within this CPU.
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
 * @singlestep_enabled: Flags for single-stepping.
 * @icount_extra: Instructions until next timer event.
 * @icount_decr: Low 16 bits: number of cycles left, only used in icount mode.
 * High 16 bits: Set to -1 to force TCG to stop executing linked TBs for this
 * CPU and return to its top level loop (even in non-icount mode).
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
 * @trace_dstate_delayed: Delayed changes to trace_dstate (includes all changes
 *                        to @trace_dstate).
 * @trace_dstate: Dynamic tracing state of events for this vCPU (bitmask).
 * @ignore_memory_transaction_failures: Cached copy of the MachineState
 *    flag of the same name: allows the board to suppress calling of the
 *    CPU do_transaction_failed hook function.
 *
 * State of one CPU core or thread.
 */
struct CPUState {
    /*< private >*/
    DeviceState parent_obj;
    /*< public >*/

    int nr_cores;
    int nr_threads;

    struct QemuThread *thread;
#ifdef _WIN32
    HANDLE hThread;
#endif
    int thread_id;
    bool running, has_waiter;
    struct QemuCond *halt_cond;
    bool thread_kicked;
    bool created;
    bool stop;
    bool stopped;
    bool unplug;
    bool crash_occurred;
    bool exit_request;
    uint32_t cflags_next_tb;
    /* updates protected by BQL */
    uint32_t interrupt_request;
    int singlestep_enabled;
    int64_t icount_budget;
    int64_t icount_extra;
    sigjmp_buf jmp_env;

    QemuMutex work_mutex;
    struct qemu_work_item *queued_work_first, *queued_work_last;

    CPUAddressSpace *cpu_ases;
    int num_ases;
    AddressSpace *as;
    MemoryRegion *memory;

    void *env_ptr; /* CPUArchState */

    /* Accessed in parallel; all accesses must be atomic */
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];

    struct GDBRegisterState *gdb_regs;
    int gdb_num_regs;
    int gdb_num_g_regs;
    QTAILQ_ENTRY(CPUState) node;

    /* ice debug support */
    QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;

    QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;
    CPUWatchpoint *watchpoint_hit;

    void *opaque;

    /* In order to avoid passing too many arguments to the MMIO helpers,
     * we store some rarely used information in the CPU context.
     */
    uintptr_t mem_io_pc;
    vaddr mem_io_vaddr;
    /*
     * This is only needed for the legacy cpu_unassigned_access() hook;
     * when all targets using it have been converted to use
     * cpu_transaction_failed() instead it can be removed.
     */
    MMUAccessType mem_io_access_type;

    int kvm_fd;
    struct KVMState *kvm_state;
    struct kvm_run *kvm_run;

    /* Used for events with 'vcpu' and *without* the 'disabled' properties */
    DECLARE_BITMAP(trace_dstate_delayed, CPU_TRACE_DSTATE_MAX_EVENTS);
    DECLARE_BITMAP(trace_dstate, CPU_TRACE_DSTATE_MAX_EVENTS);

    /* TODO Move common fields from CPUArchState here. */
    int cpu_index;
    uint32_t halted;
    uint32_t can_do_io;
    int32_t exception_index;

    /* shared by kvm, hax and hvf */
    bool vcpu_dirty;

    /* Used to keep track of an outstanding cpu throttle thread for migration
     * autoconverge
     */
    bool throttle_thread_scheduled;

    bool ignore_memory_transaction_failures;

    /* Note that this is accessed at the start of every TB via a negative
       offset from AREG0.  Leave this field at the end so as to make the
       (absolute value) offset as small as possible.  This reduces code
       size, especially for hosts without large memory offsets.  */
    union {
        uint32_t u32;
        icount_decr_u16 u16;
    } icount_decr;

    struct hax_vcpu_state *hax_vcpu;

    int hvf_fd;

    /* track IOMMUs whose translations we've cached in the TCG TLB */
    GArray *iommu_notifiers;
};

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
#ifdef USE_DIRECT_JUMP
    uint16_t jmp_insn_offset[2]; /* offset of native jump instruction */
#else
    uintptr_t jmp_target_addr[2]; /* target address for indirect jump */
#endif
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

#ifdef CONFIG_LLVM
    /* pointer to LLVM translated code */
    struct TCGLLVMContext *tcg_llvm_context;
#ifdef __cplusplus
    Function *llvm_function;
#else
    struct Function *llvm_function;
#endif
    uint8_t *llvm_tc_ptr;
    uint8_t *llvm_tc_end;
    struct TranslationBlock* llvm_tb_next[2];
#endif

};
                          

#include "panda/panda_api.h"
#include "panda/plugin.h"
#include <string.h>
#include <stdio.h>
int before_block_exec(void *env, void *tb);

int before_block_exec(void *env, void *tb){
	printf("before_block_exec called\n");
	return 0;
}


int init_plugin(void* self){
	printf("init_plugin called\n");
	panda_cb pcb = { .before_block_exec = before_block_exec };
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	return 0;
}


int main(int argc, char **argv) {
    argv[0] = strdup("/home/luke/panda_luke_new/build/i386-softmmu/qemu-system-i386");
    panda_init(argc, argv, 0);

//    panda_replay("/home/luke/recordings/recording_in_new_panda"); //not right now
    panda_load_external_plugin("null_filename", "cool_new_plugin", (void*) -1, init_plugin);
    panda_run();
}
