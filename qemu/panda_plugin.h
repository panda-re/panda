#ifndef __PANDA_PLUGIN_H__
#define __PANDA_PLUGIN_H__

#include "cpu.h"

#define MAX_PANDA_PLUGINS 16

typedef enum panda_cb_type {
    PANDA_CB_BEFORE_BLOCK,
    PANDA_CB_AFTER_BLOCK,
    PANDA_CB_MEM_READ,
    PANDA_CB_MEM_WRITE,
    PANDA_CB_HD_READ,
    PANDA_CB_HD_WRITE,
    PANDA_CB_GUEST_HYPERCALL,
    PANDA_CB_LAST,
} panda_cb_type;

typedef union panda_cb {
    int (*guest_hypercall)(CPUState *env);
    int (*before_block)(CPUState *env, TranslationBlock *tb);
    int (*after_block)(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);
} panda_cb;

// Doubly linked list that stores a callback, along with its owner
typedef struct _panda_cb_list panda_cb_list;
struct _panda_cb_list {
    panda_cb entry;
    void *owner;
    panda_cb_list *next;
    panda_cb_list *prev;
};

typedef struct panda_plugin {
    char name[256];
    void *plugin;
} panda_plugin;

void panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb);
void panda_unregister_callbacks(void *plugin);
void * panda_load_plugin(const char *filename);
void * panda_get_plugin_by_name(const char *name);
void panda_unload_plugin(void *plugin);
void panda_unload_plugins(void);

#endif
