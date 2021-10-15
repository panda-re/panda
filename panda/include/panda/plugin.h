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
#pragma once
#include "panda/debug.h"
#include "panda/cheaders.h"

#ifndef CONFIG_SOFTMMU
#include "linux-user/qemu-types.h"
#include "thunk.h"
#endif

#define MAX_PANDA_PLUGINS 16
#define MAX_PANDA_PLUGIN_ARGS 32

#include "panda/callbacks/cb-defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// Doubly linked list that stores a callback, along with its owner
typedef struct _panda_cb_list panda_cb_list;
struct _panda_cb_list {
    panda_cb_with_context entry;
    void *owner;
    panda_cb_list *next;
    panda_cb_list *prev;
    bool enabled;
    void* context;
};
panda_cb_list *panda_cb_list_next(panda_cb_list *plist);
void panda_enable_plugin(void *plugin);
void panda_disable_plugin(void *plugin);

// Structure to store metadata about a plugin
typedef struct panda_plugin {
    char name[256];     // Currently basename(filename)
    void *plugin;       // Handle to the plugin (for use with dlsym())
} panda_plugin;

panda_cb_with_context panda_get_cb_trampoline(panda_cb_type type);
void   panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb);
void   panda_register_callback_with_context(void *plugin, panda_cb_type type, panda_cb_with_context cb, void* context);
void   panda_disable_callback(void *plugin, panda_cb_type type, panda_cb cb);
void   panda_enable_callback(void *plugin, panda_cb_type type, panda_cb cb);
void   panda_unregister_callbacks(void *plugin);
bool   panda_load_plugin(const char *filename, const char *plugin_name);
bool   _panda_load_plugin(const char *filename, const char *plugin_name, bool library_mode);
bool   panda_add_arg(const char *plugin_name, const char *plugin_arg);
bool   panda_load_external_plugin(const char *filename, const char *plugin_name, void *plugin_uuid, void *init_fn_ptr);
void * panda_get_plugin_by_name(const char *name);
void   panda_unload_plugin_by_name(const char* name);
void   panda_do_unload_plugin(int index);
void   panda_unload_plugin(void *plugin);
void   panda_unload_plugin_idx(int idx);
void   panda_unload_plugins(void);

extern bool panda_update_pc;
extern bool panda_use_memcb;
extern panda_cb_list *panda_cbs[PANDA_CB_LAST];
extern bool panda_plugins_to_unload[MAX_PANDA_PLUGINS];
extern bool panda_plugin_to_unload;
extern bool panda_tb_chaining;

// this stuff is used by the new qemu cmd-line arg '-os os_name'
typedef enum OSFamilyEnum { OS_UNKNOWN, OS_WINDOWS, OS_LINUX, OS_FREEBSD } PandaOsFamily;

// these are set in panda/src/common.c via call to panda_set_os_name(os_name)
extern char *panda_os_name;           // the full name of the os, as provided by the user
extern char *panda_os_family;         // parsed os family
extern char *panda_os_variant;        // parsed os variant
extern uint32_t panda_os_bits;        // parsed os bits
extern PandaOsFamily panda_os_familyno; // numeric identifier for family



bool panda_flush_tb(void);

void panda_do_flush_tb(void);
void panda_enable_precise_pc(void);
void panda_disable_precise_pc(void);
void panda_enable_memcb(void);
void panda_disable_memcb(void);
void panda_enable_llvm(void);
void panda_enable_llvm_no_exec(void);
void panda_disable_llvm(void);
void panda_enable_llvm_helpers(void);
void panda_disable_llvm_helpers(void);
int panda_write_current_llvm_bitcode_to_file(const char* path);
uintptr_t panda_get_current_llvm_module(void);
void panda_enable_tb_chaining(void);
void panda_disable_tb_chaining(void);
void panda_memsavep(FILE *f);

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

char** str_split(char *a_str, const char a_delim);

extern gchar *panda_argv[MAX_PANDA_PLUGIN_ARGS];
extern int panda_argc;

char *panda_plugin_path(const char *name);
void panda_require_from_library(const char *plugin_name, char **plugin_args, uint32_t num_args);
void panda_require(const char *plugin_name);
bool panda_is_callback_enabled(void *plugin, panda_cb_type type, panda_cb cb);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#ifdef __cplusplus
}
#endif

#include "panda/plugin_plugin.h"


#ifdef __cplusplus
extern "C" {
#endif

#include "panda/rr/rr_log.h"
#include "panda/plog.h"

#ifdef __cplusplus
}
#endif

