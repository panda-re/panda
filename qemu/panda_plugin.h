#ifndef __PANDA_PLUGIN_H__
#define __PANDA_PLUGIN_H__

#include "cpu.h"

#define MAX_PANDA_PLUGINS 16

typedef enum panda_cb_type {
    PANDA_CB_BEFORE_BLOCK,      // Before each basic block
    PANDA_CB_AFTER_BLOCK,       // After each basic block
    PANDA_CB_INSN_TRANSLATE,    // Before an insn is translated
    PANDA_CB_INSN_EXEC,         // Before an insn is executed
    PANDA_CB_MEM_READ,          // Each memory read
    PANDA_CB_MEM_WRITE,         // Each memory write
    PANDA_CB_HD_READ,           // Each HDD read
    PANDA_CB_HD_WRITE,          // Each HDD write
    PANDA_CB_GUEST_HYPERCALL,   // Hypercall from the guest (e.g. CPUID)
    PANDA_CB_MONITOR,           // Monitor callback
    PANDA_CB_LAST,
} panda_cb_type;

// Union of all possible callback function types
typedef union panda_cb {
    // PANDA_CB_BEFORE_BLOCK
    int (*before_block)(CPUState *env, TranslationBlock *tb);
    // PANDA_CB_AFTER_BLOCK
    int (*after_block)(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);
    // PANDA_CB_INSN_EXEC
    int (*insn_exec)(CPUState *env, target_ulong pc);
    // PANDA_CB_INSN_TRANSLATE
    bool (*insn_translate)(CPUState *env, target_ulong pc);
    // PANDA_CB_GUEST_HYPERCALL
    int (*guest_hypercall)(CPUState *env);
    // PANDA_CB_MONITOR
    int (*monitor)(Monitor *mon, const char *cmd);
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

bool panda_flush_tb(void);
void panda_do_flush_tb(void);

#endif
