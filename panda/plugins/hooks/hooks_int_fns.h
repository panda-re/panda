#ifndef __HOOKS_INT_FNS_H__
#define __HOOKS_INT_FNS_H__

#include "dynamic_symbols/dynamic_symbols_int_fns.h"
#include "tcg.h"

extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

#define MAX_PROCNAME_LENGTH 256
#define MAX_PATH_LEN 256
struct hook;
struct symbol;

// Hook functions must be of this type
typedef bool (*hook_func_t)(CPUState *, TranslationBlock *, struct hook* h);

typedef bool (*dynamic_symbol_hook_func_t)(CPUState *, TranslationBlock *, struct hook* h);

typedef union hooks_panda_cb {
    void (*before_tcg_codegen)(CPUState *env, TranslationBlock *tb, TCGContext *s, struct hook*);
    void (*before_block_translate)(CPUState *env, target_ptr_t pc, struct hook*);
    void (*after_block_translate)(CPUState *env, TranslationBlock *tb, struct hook*);
    bool (*before_block_exec_invalidate_opt)(CPUState *env, TranslationBlock *tb, struct hook*);
    void (*before_block_exec)(CPUState *env, TranslationBlock *tb, struct hook*);
    void (*after_block_exec)(CPUState *env, TranslationBlock *tb, uint8_t exitCode, struct hook*);
    void (*start_block_exec)(CPUState *env, TranslationBlock *tb, struct hook*);
    void (*end_block_exec)(CPUState *env, TranslationBlock *tb, struct hook*);
} hooks_panda_cb;

enum kernel_mode{
    MODE_ANY,
    MODE_KERNEL_ONLY,
    MODE_USER_ONLY,
};

typedef struct hook {
    target_ulong addr;
    target_ulong asid;
    panda_cb_type type;
    hooks_panda_cb cb;
    enum kernel_mode km;
    bool enabled;
    struct symbol sym; //if an associated symbol exists
} hook;


struct symbol_hook {
    char name[MAX_PATH_LEN];
    target_ulong offset;
    bool hook_offset;
    char section[MAX_PATH_LEN];
    panda_cb_type type;
    hooks_panda_cb cb;
};

extern "C" void add_hook(struct hook* h);
extern "C" void enable_hooking();
extern "C" void disable_hooking();
extern "C" void add_symbol_hook(struct symbol_hook* h);

struct dynamic_symbol_hook {
    char library_name[MAX_PATH_LEN];
    char symbol[MAX_PATH_LEN];
    dynamic_symbol_hook_func_t cb;
};

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}
#endif
