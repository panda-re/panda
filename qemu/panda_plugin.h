#ifndef __PANDA_PLUGIN_H__
#define __PANDA_PLUGIN_H__

#include "cpu.h"

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

typedef struct _panda_cb_list panda_cb_list;

struct _panda_cb_list {
    panda_cb entry;
    panda_cb_list *next;
};

void register_panda_callback(panda_cb_type type, panda_cb cb);
bool load_panda_plugin(const char *filename);

#endif
