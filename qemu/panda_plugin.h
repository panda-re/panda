#ifndef __PANDA_PLUGIN_H__
#define __PANDA_PLUGIN_H__

#include "cpu.h"

#define MAX_PANDA_PLUGINS 16

typedef enum panda_cb_type {
    PANDA_CB_BEFORE_BLOCK_TRANSLATE,    // Before translating each basic block
    PANDA_CB_AFTER_BLOCK_TRANSLATE,     // After translating each basic block
    PANDA_CB_BEFORE_BLOCK_EXEC,         // Before executing each basic block (may trigger retranslation)
    PANDA_CB_AFTER_BLOCK_EXEC,          // After executing each basic block
    PANDA_CB_INSN_TRANSLATE,    // Before an insn is translated
    PANDA_CB_INSN_EXEC,         // Before an insn is executed
    PANDA_CB_MEM_READ,          // After each memory read
    PANDA_CB_MEM_WRITE,         // Before each memory write
    PANDA_CB_HD_READ,           // Each HDD read
    PANDA_CB_HD_WRITE,          // Each HDD write
    PANDA_CB_GUEST_HYPERCALL,   // Hypercall from the guest (e.g. CPUID)
    PANDA_CB_MONITOR,           // Monitor callback
    PANDA_CB_LAST,
} panda_cb_type;

// Union of all possible callback function types
typedef union panda_cb {
    /* Callback ID: PANDA_CB_BEFORE_BLOCK_EXEC

       before_block_exec: called before execution of every basic block

       Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we are about to execute

       Return value:
        true if we should invalidate the current translation block
        and retranslate, false otherwise
    */
    bool (*before_block_exec)(CPUState *env, TranslationBlock *tb);

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

    /* Callback ID: PANDA_CB_MEM_READ

       mem_read: called after memory is read
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the read
        target_ulong addr: the (virtual) address being read
        target_ulong size: the size of the read
        void *buf: pointer to the data that was read
       
       Return value:
        unused

       Notes:
        Due to the way the instrumentation is implemented, this
        callback will only be called when executing in LLVM mode.
    */
    int (*mem_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

/* Callback ID: PANDA_CB_MEM_WRITE

       mem_read: called before memory is written
       
       Arguments:
        CPUState *env: the current CPU state
        target_ulong pc: the guest PC doing the write
        target_ulong addr: the (virtual) address being written
        target_ulong size: the size of the write
        void *buf: pointer to the data that is to be written 
       
       Return value:
        unused

       Notes:
        Due to the way the instrumentation is implemented, this
        callback will only be called when executing in LLVM mode.
    */
    int (*mem_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

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
void * panda_get_plugin_by_name(const char *name);
void   panda_unload_plugin(int index);
void   panda_unload_plugins(void);

// Doesn't exist in user mode
#ifdef CONFIG_SOFTMMU
int panda_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);
#endif

int panda_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);

bool panda_flush_tb(void);

void panda_do_flush_tb(void);
void panda_enable_precise_pc(void);
void panda_disable_precise_pc(void);
void panda_enable_memcb(void);
void panda_disable_memcb(void);

extern bool panda_update_pc;
extern bool panda_use_memcb;
extern panda_cb_list *panda_cbs[PANDA_CB_LAST];

#endif
