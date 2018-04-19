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

#include "panda/debug.h"
#include "panda/cheaders.h"

#ifndef CONFIG_SOFTMMU
#include "linux-user/qemu-types.h"
#include "thunk.h"
#endif

#define MAX_PANDA_PLUGINS 16
#define MAX_PANDA_PLUGIN_ARGS 32

#ifdef __cplusplus
extern "C" {
#endif

typedef enum panda_cb_type {
    PANDA_CB_BEFORE_BLOCK_TRANSLATE,    // Before translating each basic block
    PANDA_CB_AFTER_BLOCK_TRANSLATE,     // After translating each basic block
    PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT,    // Before executing each basic block (with option to invalidate, may trigger retranslation)
    PANDA_CB_BEFORE_BLOCK_EXEC,         // Before executing each basic block
    PANDA_CB_AFTER_BLOCK_EXEC,          // After executing each basic block
    PANDA_CB_INSN_TRANSLATE,    // Before an insn is translated
    PANDA_CB_INSN_EXEC,         // Before an insn is executed

    PANDA_CB_VIRT_MEM_BEFORE_READ,
    PANDA_CB_VIRT_MEM_BEFORE_WRITE,
    PANDA_CB_PHYS_MEM_BEFORE_READ,
    PANDA_CB_PHYS_MEM_BEFORE_WRITE,

    PANDA_CB_VIRT_MEM_AFTER_READ,
    PANDA_CB_VIRT_MEM_AFTER_WRITE,
    PANDA_CB_PHYS_MEM_AFTER_READ,
    PANDA_CB_PHYS_MEM_AFTER_WRITE,


    PANDA_CB_HD_READ,           // Each HDD read
    PANDA_CB_HD_WRITE,          // Each HDD write
    PANDA_CB_GUEST_HYPERCALL,   // Hypercall from the guest (e.g. CPUID)
    PANDA_CB_MONITOR,           // Monitor callback
    PANDA_CB_CPU_RESTORE_STATE,  // In cpu_restore_state() (fault/exception)
    PANDA_CB_BEFORE_REPLAY_LOADVM,     // at start of replay, before loadvm
    PANDA_CB_ASID_CHANGED,           // When CPU asid (address space identifier) changes
    PANDA_CB_REPLAY_HD_TRANSFER,     // in replay, hd transfer
    PANDA_CB_REPLAY_NET_TRANSFER,    // in replay, transfers within network card (currently only E1000)
    PANDA_CB_REPLAY_BEFORE_DMA,      // in replay, just before RAM case of cpu_physical_mem_rw
    PANDA_CB_REPLAY_AFTER_DMA,       // in replay, just after RAM case of cpu_physical_mem_rw
    PANDA_CB_REPLAY_HANDLE_PACKET,   // in replay, packet in / out
    PANDA_CB_AFTER_MACHINE_INIT,     // Right after the machine is initialized, before any code runs

    PANDA_CB_TOP_LOOP,               // at top of loop that manages emulation.  good place to take a snapshot

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
    int (*after_block_exec)(CPUState *env, TranslationBlock *tb);

    /* Callback ID: PANDA_CB_BEFORE_BLOCK_TRANSLATE

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

    /* Callback ID: PANDA_CB_VIRT_MEM_BEFORE_READ

       virt_mem_before_read: called before memory is read

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the read
        target_ulong addr: the (virtual) address being read
        target_ulong size: the size of the read

       Return value:
        unused
    */
    int (*virt_mem_before_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);

    /* Callback ID: PANDA_CB_VIRT_MEM_BEFORE_WRITE

       virt_mem_before_write: called before memory is written
       [exists]

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the write
        target_ulong addr: the (virtual) address being written
        target_ulong size: the size of the write
        void *buf: pointer to the data that is to be written

       Return value:
        unused
    */
    int (*virt_mem_before_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

    /* Callback ID: PANDA_CB_PHYS_MEM_BEFORE_READ

       phys_mem_before_read: called after memory is read
       [new]

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the read
        target_ulong addr: the (physical) address being read
        target_ulong size: the size of the read

       Return value:
        unused
    */
    int (*phys_mem_before_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);

    /* Callback ID: PANDA_CB_PHYS_MEM_BEFORE_WRITE

       phys_mem_write: called before memory is written
       [exists]

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the write
        target_ulong addr: the (physical) address being written
        target_ulong size: the size of the write
        void *buf: pointer to the data that is to be written

       Return value:
        unused
    */
    int (*phys_mem_before_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

    /* Callback ID: PANDA_CB_VIRT_MEM_AFTER_READ

       virt_mem_after_read: called after memory is read
       [exists]

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the read
        target_ulong addr: the (virtual) address being read
        target_ulong size: the size of the read
        void *buf: pointer to data just read

       Return value:
        unused
    */
    int (*virt_mem_after_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

    /* Callback ID: PANDA_CB_VIRT_MEM_AFTER_WRITE

       virt_mem_after_write: called after memory is written
       [new]

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the write
        target_ulong addr: the (virtual) address being written
        target_ulong size: the size of the write
        void *buf: pointer to the data that was written

       Return value:
        unused
    */
    int (*virt_mem_after_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

    /* Callback ID: PANDA_CB_PHYS_MEM_AFTER_READ

       phys_mem_after_read: called after memory is read
       [exists]

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the read
        target_ulong addr: the (physical) address being read
        target_ulong size: the size of the read
        void *buf: pointer to data just read

       Return value:
        unused
    */
    int (*phys_mem_after_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

    /* Callback ID: PANDA_CB_PHYS_MEM_AFTER_WRITE

       phys_mem_write: called after memory is written
       [new]

       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the write
        target_ulong addr: the (physical) address being written
        target_ulong size: the size of the write
        void *buf: pointer to the data that was written

       Return value:
        unused
    */
    int (*phys_mem_after_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

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

       before_loadvm: called at start of replay, before loadvm is called.
        This allows us to hook devices' loadvm handlers.
        Remember to unregister the existing handler for the device first.
        See the example in the sample plugin.

        Arguments:

        Return value:
         unused
    */
    int (*before_loadvm)(void);

    /* Callback ID: PANDA_CB_ASID_CHANGED

       asid_changed: Called when asid changes.

       Arguments:
        CPUState* env: pointer to CPUState
        target_ulong oldval: old asid value
        target_ulong newval: new asid value

       Return value:
        unused
    */
    int (*asid_changed)(CPUState *env, target_ulong oldval, target_ulong newval);

    /* Callback ID:     PANDA_CB_REPLAY_HD_TRANSFER,

       In replay only, some kind of data transfer involving hard drive.
       NB: We are neither before nor after, really.
       In replay the transfer doesn't really happen.
       We are *at* the point at which it happened, really.

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

    /* Callback ID:     PANDA_CB_REPLAY_BEFORE_DMA,

       In replay only, we are about to dma between qemu buffer and guest memory

       Arguments:
        CPUState* env:       pointer to CPUState
        uint32_t is_write:   type of transfer going on    (is_write == 1 means IO -> RAM else RAM -> IO)
        uint8_t* buf         the QEMU device's buffer in QEMU's virtual memory
        uint64_t paddr       "physical" address of guest RAM
        uint32_t num_bytes:  size of transfer
    */
    int (*replay_before_dma)(CPUState *env, uint32_t is_write, uint8_t* src_addr, uint64_t dest_addr, uint32_t num_bytes);

    /* Callback ID:     PANDA_CB_REPLAY_AFTER_DMA,

       In replay only, we are about to dma between qemu buffer and guest memory

       Arguments:
        CPUState* env:       pointer to CPUState
        uint32_t is_write:   type of transfer going on    (is_write == 1 means IO -> RAM else RAM -> IO)
        uint8_t* buf         the QEMU device's buffer in QEMU's virtual memory
        uint64_t paddr       "physical" address of guest RAM
        uint32_t num_bytes:  size of transfer
    */
    int (*replay_after_dma)(CPUState *env, uint32_t is_write, uint8_t* src_addr, uint64_t dest_addr, uint32_t num_bytes);

    /* Callback ID:   PANDA_CB_REPLAY_HANDLE_PACKET,

       In replay only, we have a packet (incoming / outgoing) in hand.

       Arguments:
        CPUState *env          pointer to CPUState
        uint8_t *buf           buffer containing packet data
        int size               num bytes in buffer
        uint8_t direction      XXX read or write.  not sure which is which.
        uint64_t old_buf_addr  XXX this is a mystery
    */
    int (*replay_handle_packet)(CPUState *env, uint8_t *buf, int size, uint8_t direction, uint64_t old_buf_addr);

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

    /* Callback ID:     PANDA_CB_AFTER_MACHINE_INIT

       after_machine_init: Called right after the machine has been initialized,
        but before any guest code runs.

       Arguments:
        void *cpu_env: pointer to CPUState

       Return value:
        unused

       Notes:
        This callback allows initialization of components that need access to
        the RAM, CPU object, etc.
        E.g. for the taint2 plugin, this is the appropriate place to call
        taint2_enable_taint().
    */
    void (*after_machine_init)(CPUState *env);

    /* Callback ID:     PANDA_CB_TOP_LOOP

       top_loop: Called at the top of the loop that manages emulation.

       Arguments:
        void *cpu_env: pointer to CPUState

       Return value:
        unused
     */
    void (*top_loop)(CPUState *env);

    /* Dummy union member.

       This union only contains function pointers.
       Using the cbaddr member one can compare if two union instances
       point to the same callback function. In principle, any other
       member could be used instead.
       However, cbaddr provides neutral semantics for the comparisson.
    */
    void (* cbaddr)(void);
} panda_cb;

// Doubly linked list that stores a callback, along with its owner
typedef struct _panda_cb_list panda_cb_list;
struct _panda_cb_list {
    panda_cb entry;
    void *owner;
    panda_cb_list *next;
    panda_cb_list *prev;
    bool enabled;
};
panda_cb_list* panda_cb_list_next(panda_cb_list* plist);
void panda_enable_plugin(void *plugin);
void panda_disable_plugin(void *plugin);

// Structure to store metadata about a plugin
typedef struct panda_plugin {
    char name[256];     // Currently basename(filename)
    void *plugin;       // Handle to the plugin (for use with dlsym())
} panda_plugin;

void   panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb);
void   panda_disable_callback(void *plugin, panda_cb_type type, panda_cb cb);
void   panda_enable_callback(void *plugin, panda_cb_type type, panda_cb cb);
void   panda_unregister_callbacks(void *plugin);
bool   panda_load_plugin(const char *filename, const char *plugin_name);
bool   panda_add_arg(const char *plugin_name, const char *plugin_arg);
void * panda_get_plugin_by_name(const char *name);
void   panda_do_unload_plugin(int index);
void   panda_unload_plugin(void* plugin);
void   panda_unload_plugin_idx(int idx);
void   panda_unload_plugins(void);


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

extern const gchar *panda_argv[MAX_PANDA_PLUGIN_ARGS];
extern int panda_argc;


// this stuff is used by the new qemu cmd-line arg '-os os_name'
typedef enum OSFamilyEnum { OS_UNKNOWN, OS_WINDOWS, OS_LINUX } PandaOsFamily;

// these are set in panda_common.c via call to panda_set_os_name(os_name)
extern char *panda_os_name;           // the full name of the os, as provided by the user
extern char *panda_os_family;         // parsed os family
extern char *panda_os_variant;        // parsed os variant
extern uint32_t panda_os_bits;        // parsed os bits
extern PandaOsFamily panda_os_familyno; // numeric identifier for family


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
    char *plugin_name;
} panda_arg_list;

// Parse out arguments and return them to caller
panda_arg_list *panda_get_args(const char *plugin_name);
// Free a list of parsed arguments
void panda_free_args(panda_arg_list *args);

target_ulong panda_parse_ulong(panda_arg_list *args, const char *argname, target_ulong defval);
target_ulong panda_parse_ulong_req(panda_arg_list *args, const char *argname, const char *help);
target_ulong panda_parse_ulong_opt(panda_arg_list *args, const char *argname, target_ulong defval, const char *help);
uint32_t panda_parse_uint32(panda_arg_list *args, const char *argname, uint32_t defval);
uint32_t panda_parse_uint32_req(panda_arg_list *args, const char *argname, const char *help);
uint32_t panda_parse_uint32_opt(panda_arg_list *args, const char *argname, uint32_t defval, const char *help);
uint64_t panda_parse_uint64(panda_arg_list *args, const char *argname, uint64_t defval);
uint64_t panda_parse_uint64_req(panda_arg_list *args, const char *argname, const char *help);
uint64_t panda_parse_uint64_opt(panda_arg_list *args, const char *argname, uint64_t defval, const char *help);
double panda_parse_double(panda_arg_list *args, const char *argname, double defval);
double panda_parse_double_req(panda_arg_list *args, const char *argname, const char *help);
double panda_parse_double_opt(panda_arg_list *args, const char *argname, double defval, const char *help);
// Returns true if arg present, unless arg=false or arg=no exists.
bool panda_parse_bool(panda_arg_list *args, const char *argname);
bool panda_parse_bool_req(panda_arg_list *args, const char *argname, const char *help);
bool panda_parse_bool_opt(panda_arg_list *args, const char *argname, const char *help);
const char *panda_parse_string(panda_arg_list *args, const char *argname, const char *defval);
const char *panda_parse_string_req(panda_arg_list *args, const char *argname, const char *help);
const char *panda_parse_string_opt(panda_arg_list *args, const char *argname, const char *defval, const char *help);

char** str_split(char* a_str, const char a_delim);

char *panda_plugin_path(const char *name);
void panda_require(const char *plugin_name);

void panda_cleanup(void);

#ifdef __cplusplus
}
#endif

#include "panda/plugin_plugin.h"


#ifdef __cplusplus
extern "C" {
#endif

#include "panda/rr/rr_log.h"
#include "panda/plog.h"
#include "panda/addr.h"

#ifdef __cplusplus
}
#endif


#endif
