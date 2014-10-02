/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
#ifndef __PANDA_PLUGIN_H__
#define __PANDA_PLUGIN_H__

#include "config.h"
#include "cpu.h"

#ifndef CONFIG_SOFTMMU
#include "linux-user/qemu-types.h"
#include "thunk.h"
#endif

#define MAX_PANDA_PLUGINS 16
#define MAX_PANDA_PLUGIN_ARGS 32

typedef enum panda_cb_type {
    PANDA_CB_BEFORE_BLOCK_TRANSLATE,    // Before translating each basic block
    PANDA_CB_AFTER_BLOCK_TRANSLATE,     // After translating each basic block
    PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT,    // Before executing each basic block (with option to invalidate, may trigger retranslation)
    PANDA_CB_BEFORE_BLOCK_EXEC,         // Before executing each basic block
    PANDA_CB_AFTER_BLOCK_EXEC,          // After executing each basic block
    PANDA_CB_INSN_TRANSLATE,    // Before an insn is translated
    PANDA_CB_INSN_EXEC,         // Before an insn is executed
    PANDA_CB_VIRT_MEM_READ,     // After each memory read (virtual addr.)
    PANDA_CB_VIRT_MEM_WRITE,    // Before each memory write (virtual addr.)
    PANDA_CB_PHYS_MEM_READ,     // After each memory read (physical addr.)
    PANDA_CB_PHYS_MEM_WRITE,    // Before each memory write (physical addr.)
    PANDA_CB_HD_READ,           // Each HDD read
    PANDA_CB_HD_WRITE,          // Each HDD write
    PANDA_CB_GUEST_HYPERCALL,   // Hypercall from the guest (e.g. CPUID)
    PANDA_CB_MONITOR,           // Monitor callback
    PANDA_CB_CPU_RESTORE_STATE,  // In cpu_restore_state() (fault/exception)
    PANDA_CB_BEFORE_REPLAY_LOADVM,     // at start of replay, before loadvm
#ifndef CONFIG_SOFTMMU          // *** Only callbacks for QEMU user mode *** //
    PANDA_CB_USER_BEFORE_SYSCALL, // before system call
    PANDA_CB_USER_AFTER_SYSCALL,  // after system call (with return value)
#endif
#ifdef CONFIG_PANDA_VMI
    PANDA_CB_VMI_AFTER_FORK,    // After returning from fork()
    PANDA_CB_VMI_AFTER_EXEC,    // After returning from exec()
    PANDA_CB_VMI_AFTER_CLONE,    // After returning from clone()
#endif
    PANDA_CB_VMI_PGD_CHANGED,   // After CPU's PGD is written to
    PANDA_CB_REPLAY_HD_TRANSFER,    // in replay, hd transfer
    PANDA_CB_REPLAY_NET_TRANSFER,   // in replay, transfers within network card (currently only E1000)
    PANDA_CB_REPLAY_BEFORE_CPU_PHYSICAL_MEM_RW_RAM,  // in replay, just before RAM case of cpu_physical_mem_rw
    PANDA_CB_REPLAY_HANDLE_PACKET,    // in replay, packet in / out
    PANDA_CB_LAST
} panda_cb_type;

// Union of all possible callback function types
typedef union panda_cb {
    /* Callback ID: PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT

       before_block_exec_invalidate_opt: called before execution of every basic
       block, with the option to invalidate the TB

       Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we are about to execute

       Return value:
        true if we should invalidate the current translation block
        and retranslate, false otherwise
    */
    bool (*before_block_exec_invalidate_opt)(CPUState *env, TranslationBlock *tb);
    
    /* Callback ID: PANDA_CB_BEFORE_BLOCK_EXEC

       before_block_exec: called before execution of every basic block

       Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we are about to execute

       Return value:
        unused
    */
    int (*before_block_exec)(CPUState *env, TranslationBlock *tb);

    /* Callback ID: PANDA_CB_AFTER_BLOCK_EXEC

       after_block_exec: called after execution of every basic block

       Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we just executed
        TranslationBlock *next_tb: the TB we will execute next (may be NULL)

       Return value:
        unused
    */
    int (*after_block_exec)(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);

    /* 
    // Callback ID: PANDA_CB_BEFORE_BLOCK_TRANSLATE

       before_block_translate: called before translation of each basic block

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC we are about to translate

       Return value:
        unused

    */
    int (*before_block_translate)(CPUState *env, target_ulong pc);
    
    /* Callback ID: PANDA_CB_AFTER_BLOCK_TRANSLATE
       
       after_block_translate: called after the translation of each basic block
       
       Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we just translated
       
       Return value:
        unused

       Notes:
        This is a good place to perform extra passes over the generated
        code (particularly by manipulating the LLVM code)
        FIXME: How would this actually work? By this point the out ASM
            has already been generated. Modify the IR and then regenerate?
         
    */
    int (*after_block_translate)(CPUState *env, TranslationBlock *tb);

    /* Callback ID: PANDA_CB_INSN_TRANSLATE

       insn_translate: called before the translation of each instruction
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC we are about to translate
       
       Return value:
        true if PANDA should insert instrumentation into the generated code,
        false otherwise

       Notes:
        This allows a plugin writer to instrument only a small number of
        instructions, avoiding the performance hit of instrumenting everything.
        If you do want to instrument every single instruction, just return
        true. See the documentation for PANDA_CB_INSN_EXEC for more detail.
 
    */
    bool (*insn_translate)(CPUState *env, target_ulong pc);

    /* Callback ID: PANDA_CB_INSN_EXEC

       insn_exec: called before execution of any instruction identified
        by the PANDA_CB_INSN_TRANSLATE callback
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC we are about to execute
       
       Return value:
        unused

       Notes:
        This instrumentation is implemented by generating a call to a
        helper function just before the instruction itself is generated.
        This is fairly expensive, which is why it's only enabled via
        the PANDA_CB_INSN_TRANSLATE callback.
    
    */
    int (*insn_exec)(CPUState *env, target_ulong pc);

    /* Callback ID: PANDA_CB_GUEST_HYPERCALL

       guest_hypercall: called when a program inside the guest makes a
        hypercall to pass information from inside the guest to a plugin
       
       Arguments:
        CPUState *env: the current CPU state
       
       Return value:
        unused

       Notes:
        On x86, this is called whenever CPUID is executed. Plugins then
        check for magic values in the registers to determine if it really
        is a guest hypercall. Parameters can be passed in other registers.
        
        S2E accomplishes this by using a (currently) undefined opcode. We
        have instead opted to use an existing instruction to make development
        easier (we can use inline asm rather than defining the raw bytes).
        
        AMD's SVM and Intel's VT define hypercalls, but they are privileged
        instructinos, meaning the guest must be in ring 0 to execute them.
 
    */
    int (*guest_hypercall)(CPUState *env);

    /* Callback ID: PANDA_CB_MONITOR

       monitor: called when someone uses the plugin_cmd monitor command

       Arguments:
        Monitor *mon: a pointer to the Monitor
        const char *cmd: the command string passed to plugin_cmd

       Return value:
        unused

       Notes:
        The command is passed as a single string. No parsing is performed
        on the string before it is passed to the plugin, so each plugin
        must parse the string as it deems appropriate (e.g. by using strtok
        and getopt) to do more complex option processing.

        It is recommended that each plugin implementing this callback respond
        to the "help" message by listing the commands supported by the plugin.

        Note that every loaded plugin will have the opportunity to respond to
        each plugin_cmd; thus it is a good idea to ensure that your plugin's
        monitor commands are uniquely named, e.g. by using the plugin name
        as a prefix ("sample_do_foo" rather than "do_foo").

    */
    int (*monitor)(Monitor *mon, const char *cmd);

    /* Callback ID: PANDA_CB_VIRT_MEM_READ

       virt_mem_read: called after memory is read
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the read
        target_ulong addr: the (virtual) address being read
        target_ulong size: the size of the read
        void *buf: pointer to the data that was read
       
       Return value:
        unused

    */
    int (*virt_mem_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

/* Callback ID: PANDA_CB_VIRT_MEM_WRITE

       virt_mem_write: called before memory is written
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the write
        target_ulong addr: the (virtual) address being written
        target_ulong size: the size of the write
        void *buf: pointer to the data that is to be written 
       
       Return value:
        unused

    */
    int (*virt_mem_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

    /* Callback ID: PANDA_CB_PHYS_MEM_READ

       phys_mem_read: called after memory is read
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the read
        target_ulong addr: the (physical) address being read
        target_ulong size: the size of the read
        void *buf: pointer to the data that was read
       
       Return value:
        unused

    */
    int (*phys_mem_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

/* Callback ID: PANDA_CB_PHYS_MEM_WRITE

       phys_mem_write: called before memory is written
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the write
        target_ulong addr: the (physical) address being written
        target_ulong size: the size of the write
        void *buf: pointer to the data that is to be written 
       
       Return value:
        unused

    */
    int (*phys_mem_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

/* Callback ID: PANDA_CB_CPU_RESTORE_STATE

       cb_cpu_restore_state: called inside of cpu_restore_state(), when there is
        a CPU fault/exception
       
       Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the current translation block
       
       Return value:
        unused

*/
    int (*cb_cpu_restore_state)(CPUState *env, TranslationBlock *tb);

/* Callback ID: PANDA_CB_BEFORE_LOADVM
 *      before_loadvm: called at start of replay, before loadvm is called
 *      This allows us to hook devices' loadvm handlers (remember to unregister
 *      the existing handler for the device first)
 *
 *      See the example in the sample plugin.
 * 
 *      Arguments:
 * 
 *      Return value:
 *       unused
 * 
 */
    int (*before_loadvm)(void);
    
    
/* User-mode only callbacks:
 * We currently only support syscalls.  If you are particularly concerned about
 * arguments, look to linux-user/syscall.c for how to process them.
 */
#ifndef CONFIG_SOFTMMU

/* Callback ID: PANDA_CB_USER_BEFORE_SYSCALL

       user_before_syscall: Called before a syscall for QEMU user mode
       
       Arguments:
        void *cpu_env: pointer to CPUState
        bitmask_transtbl *fcntl_flags_tbl: syscall flags table from syscall.c
        int num: syscall number
        abi_long arg1..arg8: system call arguments
       
       Return value:
        unused

       Notes:
        Some system call arguments need some additional processing, as evident
        in linux-user/syscall.c.  If your plugin is particularly interested in
        system call arguments, be sure to process them in similar ways.
*/
    int (*user_before_syscall)(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                               int num, abi_long arg1, abi_long arg2, abi_long
                               arg3, abi_long arg4, abi_long arg5,
                               abi_long arg6, abi_long arg7, abi_long arg8);

/* Callback ID: PANDA_CB_USER_AFTER_SYSCALL

       user_after_syscall: Called after a syscall for QEMU user mode
       
       Arguments:
        void *cpu_env: pointer to CPUState
        bitmask_transtbl *fcntl_flags_tbl: syscall flags table from syscall.c
        int num: syscall number
        abi_long arg1..arg8: system call arguments
        void *p: void pointer used for processing of some arguments
        abi_long ret: syscall return value
       
       Return value:
        unused

       Notes:
        Some system call arguments need some additional processing, as evident
        in linux-user/syscall.c.  If your plugin is particularly interested in
        system call arguments, be sure to process them in similar ways.
*/
    int (*user_after_syscall)(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                              int num, abi_long arg1, abi_long arg2, abi_long
                              arg3, abi_long arg4, abi_long arg5, abi_long arg6,
                              abi_long arg7, abi_long arg8, void *p,
                              abi_long ret);

#endif // CONFIG_SOFTMMU

#ifdef CONFIG_PANDA_VMI
    
/* Callback ID: PANDA_CB_VMI_AFTER_FORK
 * 
 *      return_from_fork: Called after fork returns
 *      Arguments:
 *       void *cpu_env: pointer to CPUState
 *      
 *      Return value:
 *       unused
 */
    int (*return_from_fork)(CPUState *env);

/* Callback ID: PANDA_CB_VMI_AFTER_EXEC
 * 
 *      return_from_exec: Called after exec returns
 *      Arguments:
 *       CPUState *env: pointer to CPUState
 * 
 *      Return value:
 *       unused
 */
    int (*return_from_exec)(CPUState *env);

/* Callback ID: PANDA_CB_VMI_AFTER_CLONE
 * 
 *      return_from_exec: Called after clone returns
 *      Arguments:
 *       CPUState *env: pointer to CPUState
 * 
 *      Return value:
 *       unused
 */
    int (*return_from_clone)(CPUState *env);
#endif // CONFIG_PANDA_VMI

/* Callback ID: PANDA_CB_VMI_PGD_CHANGED
 * 
 *      after_PGD_write: Called after new PGD written to CPU hw
 *      Arguments:
 *       CPUState* env: pointer to CPUState
 *       target_ulong oldval: old PGD value
 *       target_ulong newval: new PGD value
 * 
 *      Return value:
 *       unused
 */
    int (*after_PGD_write)(CPUState *env, target_ulong oldval, target_ulong newval);

/* Callback ID:     PANDA_CB_REPLAY_HD_TRANSFER,   
 
       In replay only, some kind of data transfer involving hard drive.
       NB: We are neither before nor after, really.  In replay the transfer
       doesn't really happen.  We are *at* the point at which it happened, really.
       Arguments:
        CPUState* env: pointer to CPUState
        uint32_t type:        type of transfer  (Hd_transfer_type)
        uint64_t src_addr:    address for src
        uint64_t dest_addr:   address for dest
        uint32_t num_bytes:   size of transfer in bytes
      
       Return value:
        unused
 */
  int (*replay_hd_transfer)(CPUState *env, uint32_t type, uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes);

/* Callback ID:     PANDA_CB_REPLAY_BEFORE_CPU_PHYSICAL_MEM_RW_RAM,

   In replay only, we are about to dma between qemu buffer and guest memory

   Arguments:
   CPUState* env:       pointer to CPUState
   uint32_t is_write:   type of transfer going on    (is_write == 1 means IO -> RAM else RAM -> IO)
   uint8_t* buf         the QEMU device's buffer in QEMU's virtual memory
   uint64_t paddr       "physical" address of guest RAM
   uint32_t num_bytes:  size of transfer
*/
    int (*replay_before_cpu_physical_mem_rw_ram)(CPUState *env, uint32_t is_write, uint8_t* src_addr, uint64_t dest_addr, uint32_t num_bytes);


  /* Callback ID:   PANDA_CB_REPLAY_HANDLE_PACKET,

     In replay only, we have a packet (incoming / outgoing) in hand.
     
     Arguments:
     CPUState *env          pointer to CPUState
     uint8_t *buf           buffer containing packet data
     int size               num bytes in buffer
     uint8_t direction      XXX read or write.  not sure which is which.
     uint64_t old_buf_addr  XXX this is a mystery
  */

  int (*replay_handle_packet)(CPUState *env, uint8_t *buf, int size, uint8_t
    direction, uint64_t old_buf_addr);

/* Callback ID:     PANDA_CB_REPLAY_NET_TRANSFER,   
 
       In replay only, some kind of data transfer within the network card
       (currently, only the E1000 is supported).  NB: We are neither before nor
       after, really.  In replay the transfer doesn't really happen.  We are
       *at* the point at which it happened, really.
       Arguments:
        CPUState* env:        pointer to CPUState
        uint32_t type:        type of transfer  (Net_transfer_type)
        uint64_t src_addr:    address for src
        uint64_t dest_addr:   address for dest
        uint32_t num_bytes:   size of transfer in bytes
      
       Return value:
        unused
 */
  int (*replay_net_transfer)(CPUState *env, uint32_t type, uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes);

} panda_cb;

// Doubly linked list that stores a callback, along with its owner
typedef struct _panda_cb_list panda_cb_list;
struct _panda_cb_list {
    panda_cb entry;
    void *owner;
    panda_cb_list *next;
    panda_cb_list *prev;
};

// Structure to store metadata about a plugin
typedef struct panda_plugin {
    char name[256];     // Currently basename(filename)
    void *plugin;       // Handle to the plugin (for use with dlsym())
} panda_plugin;

void   panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb);
void   panda_unregister_callbacks(void *plugin);
bool   panda_load_plugin(const char *filename);
bool   panda_add_arg(const char *arg, int arglen);
void * panda_get_plugin_by_name(const char *name);
void   panda_do_unload_plugin(int index);
void   panda_unload_plugin(int index);
void   panda_unload_plugins(void);

// Doesn't exist in user mode
#ifdef CONFIG_SOFTMMU
int panda_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);
target_phys_addr_t panda_virt_to_phys(CPUState *env, target_ulong addr);
#endif

// is_write == 1 means this is a write to the virtual memory addr of the contents of buf.
// is_write == 0 is a read from that addr into buf.  
int panda_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);

bool panda_flush_tb(void);

void panda_do_flush_tb(void);
void panda_enable_precise_pc(void);
void panda_disable_precise_pc(void);
void panda_enable_memcb(void);
void panda_disable_memcb(void);
void panda_enable_llvm(void);
void panda_disable_llvm(void);
void panda_enable_llvm_helpers(void);
void panda_disable_llvm_helpers(void);
void panda_enable_tb_chaining(void);
void panda_disable_tb_chaining(void);
void panda_memsavep(FILE *f);

extern bool panda_update_pc;
extern bool panda_use_memcb;
extern panda_cb_list *panda_cbs[PANDA_CB_LAST];
extern bool panda_plugins_to_unload[MAX_PANDA_PLUGINS];
extern bool panda_plugin_to_unload;
extern bool panda_tb_chaining;

extern char panda_argv[MAX_PANDA_PLUGIN_ARGS][256];
extern int panda_argc;

// Struct for holding a parsed key/value pair from
// a -panda-arg plugin:key=value style argument.
typedef struct panda_arg {
    char *argptr;   // For internal use only
    char *key;      // Pointer to the key string
    char *value;    // Pointer to the value string
} panda_arg;

typedef struct panda_arg_list {
    int nargs;
    panda_arg *list;
} panda_arg_list;

// Parse out arguments and return them to caller
panda_arg_list *panda_get_args(const char *plugin_name);
// Free a list of parsed arguments
void panda_free_args(panda_arg_list *args);

target_ulong panda_parse_ulong(panda_arg_list *args, const char *argname, target_ulong defval);
uint64_t panda_parse_uint64(panda_arg_list *args, const char *argname, uint64_t defval);
double panda_parse_double(panda_arg_list *args, const char *argname, double defval);
const char *panda_parse_string(panda_arg_list *args, const char *argname, const char *defval);

#endif
