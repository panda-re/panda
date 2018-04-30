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
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <glib.h>
#include <libgen.h>

#include "panda/plugin.h"
#include "qapi/qmp/qdict.h"
#include "qmp-commands.h"
#include "hmp.h"
#include "qapi/error.h"
#include "monitor/monitor.h"

#ifdef CONFIG_LLVM
//#include "panda/panda_helper_call_morph.h"
#include "tcg.h"
#include "panda/tcg-llvm.h"
#include "panda/helper_runtime.h"
#endif

#include "panda/common.h"

const gchar *panda_bool_true_strings[] =  {"y", "yes", "true", "1", NULL};
const gchar *panda_bool_false_strings[] = {"n", "no", "false", "0", NULL};

#if 0
###########################################################
WARNING: This is all gloriously thread-unsafe!!!
###########################################################
#endif

// Array of pointers to PANDA callback lists, one per callback type
panda_cb_list *panda_cbs[PANDA_CB_LAST];

// Storage for command line options
const gchar *panda_argv[MAX_PANDA_PLUGIN_ARGS];
int panda_argc;

int nb_panda_plugins = 0;
panda_plugin panda_plugins[MAX_PANDA_PLUGINS];

bool panda_plugins_to_unload[MAX_PANDA_PLUGINS];

bool panda_plugin_to_unload = false;

int nb_panda_plugins_loaded = 0;
char *panda_plugins_loaded[MAX_PANDA_PLUGINS];

bool panda_please_flush_tb = false;
bool panda_update_pc = false;
bool panda_use_memcb = false;
bool panda_tb_chaining = true;

bool panda_help_wanted = false;
bool panda_plugin_load_failed = false;
bool panda_abort_requested = false;

bool panda_exit_loop = false;

bool panda_add_arg(const char *plugin_name, const char *plugin_arg) {
    if (plugin_name == NULL)    // PANDA argument
        panda_argv[panda_argc++] = g_strdup(plugin_arg);
    else                        // PANDA plugin argument
        panda_argv[panda_argc++] = g_strdup_printf("%s:%s", plugin_name, plugin_arg);
    return true;
}

// Forward declaration
static void panda_args_set_help_wanted(const char *);

bool panda_load_plugin(const char *filename, const char *plugin_name) {
    // don't load the same plugin twice
    uint32_t i;
    for (i=0; i<nb_panda_plugins_loaded; i++) {
        if (0 == (strcmp(filename, panda_plugins_loaded[i]))) {
            fprintf(stderr, PANDA_MSG_FMT "%s already loaded\n", PANDA_CORE_NAME, filename);
            return true;
        }
    }    
    // NB: this is really a list of plugins for which we have started loading 
    // and not yet called init_plugin fn.  needed to avoid infinite loop with panda_require  
    panda_plugins_loaded[nb_panda_plugins_loaded] = strdup(filename);
    nb_panda_plugins_loaded ++;
    void *plugin = dlopen(filename, RTLD_NOW);
    if(!plugin) {
        fprintf(stderr, "Failed to load %s: %s\n", filename, dlerror());
        return false;
    }
    bool (*init_fn)(void *) = dlsym(plugin, "init_plugin");
    if(!init_fn) {
        fprintf(stderr, "Couldn't get symbol %s: %s\n", "init_plugin", dlerror());
        dlclose(plugin);
        return false;
    }
    // populate this element in list *before* calling init_fn, please.
    // otherwise, when osi panda_requires win7x86intro and that does some PPP_REG_CB("osi"..),
    // that will fail bc it traverses this list to obtain osi handle.  ugh!
    panda_plugins[nb_panda_plugins].plugin = plugin;
    strncpy(panda_plugins[nb_panda_plugins].name, basename((char *) filename), 256);
    nb_panda_plugins++;
    fprintf(stderr, PANDA_MSG_FMT "initializing %s\n", PANDA_CORE_NAME, plugin_name ? plugin_name : filename);
    panda_help_wanted = false;
    panda_args_set_help_wanted(plugin_name);
    if (panda_help_wanted) {
        printf("Options for plugin %s:\n", plugin_name); 
        fprintf(stderr, "PLUGIN              ARGUMENT                REQUIRED        DESCRIPTION\n");
        fprintf(stderr, "======              ========                ========        ===========\n");
    }
    if(init_fn(plugin) && !panda_plugin_load_failed) {
        // TRL: Don't do this here!  See above
        //        panda_plugins[nb_panda_plugins].plugin = plugin;
        //        strncpy(panda_plugins[nb_panda_plugins].name, basename((char *) filename), 256);
        //        nb_panda_plugins++;
        return true;
    }
    else {
        dlclose(plugin);
        return false;
    }
}

extern const char *qemu_file;

// translate plugin name into path to .so
char *panda_plugin_path(const char *plugin_name) {    
    char *plugin_path = NULL;
    const char *plugin_dir = g_getenv("PANDA_PLUGIN_DIR");

    if (plugin_dir != NULL) {
        plugin_path = g_strdup_printf("%s/panda_%s.so", plugin_dir, plugin_name);
    } else {
        char *dir = g_path_get_dirname(qemu_file);
        plugin_path = g_strdup_printf("%s/panda/plugins/panda_%s.so", dir, plugin_name);
        g_free(dir);
    }
    return plugin_path;
}


void panda_require(const char *plugin_name) {
    // If we're printing help, panda_require will be a no-op.
    if (panda_help_wanted) return;

    fprintf(stderr, PANDA_MSG_FMT "loading required plugin %s\n", PANDA_CORE_NAME, plugin_name);

    // translate plugin name into a path to .so
    char *plugin_path = panda_plugin_path(plugin_name);

    // load plugin same as in vl.c
    if (!panda_load_plugin(plugin_path, plugin_name)) {
        fprintf(stderr, PANDA_MSG_FMT "FAILED to load required plugin %s from %s\n", PANDA_CORE_NAME, plugin_name, plugin_path);
        abort();
    }
    g_free(plugin_path);
}

    

// Internal: remove a plugin from the global array
static void panda_delete_plugin(int i) {
    if (i != nb_panda_plugins - 1) { // not the last element
        memmove(&panda_plugins[i], &panda_plugins[i+1], (nb_panda_plugins - i - 1)*sizeof(panda_plugin));
    }
    nb_panda_plugins--;
}

void panda_do_unload_plugin(int plugin_idx){
    void *plugin = panda_plugins[plugin_idx].plugin;
    void (*uninit_fn)(void *) = dlsym(plugin, "uninit_plugin");
    if(!uninit_fn) {
        fprintf(stderr, "Couldn't get symbol %s: %s\n", "uninit_plugin", dlerror());
    }
    else {
        uninit_fn(plugin);
    }
    panda_unregister_callbacks(plugin);
    panda_delete_plugin(plugin_idx);
    dlclose(plugin);
}

void panda_unload_plugin(void* plugin) {
    int i;
    for (i = 0; i < nb_panda_plugins; i++) {
        if (panda_plugins[i].plugin == plugin) {
            panda_unload_plugin_idx(i);
            break;
        }
    }
}

void panda_unload_plugin_idx(int plugin_idx) {
    if (plugin_idx >= nb_panda_plugins || plugin_idx < 0) {
        return;
    }
    panda_plugin_to_unload = true;
    panda_plugins_to_unload[plugin_idx] = true;
}

void panda_unload_plugins(void) {
    // Unload them starting from the end to avoid having to shuffle everything
    // down each time
    while (nb_panda_plugins > 0) {
        panda_do_unload_plugin(nb_panda_plugins - 1);
    }
}

void * panda_get_plugin_by_name(const char *plugin_name) {
    int i;
    for (i = 0; i < nb_panda_plugins; i++) {
        if (strncmp(panda_plugins[i].name, plugin_name, 256) == 0)
            return panda_plugins[i].plugin;
    }
    return NULL;
}

/**
 * @brief Adds callback to the tail of the callback list and enables it.
 *
 * The order of callback registration will determine the order in which
 * callbacks of the same type will be invoked.
 *
 * @note Registering a callback function twice from the same plugin will trigger
 * an assertion error.
 */
void panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb) {
    panda_cb_list *plist_last = NULL;

    panda_cb_list *new_list = g_new0(panda_cb_list, 1);
    new_list->entry = cb;
    new_list->owner = plugin;
    new_list->enabled = true;

    if(panda_cbs[type] != NULL) {
        for(panda_cb_list *plist = panda_cbs[type]; plist != NULL; plist = plist->next) {
            // the same plugin can register the same callback function only once
            assert(!(plist->owner == plugin && (plist->entry.cbaddr) == cb.cbaddr));
            plist_last = plist;
        }
        plist_last->next = new_list;
        new_list->prev = plist_last;
    }
    else {
        panda_cbs[type] = new_list;
    }
}

/**
 * @brief Disables the execution of the specified callback.
 *
 * This is done by setting the `enabled` flag to `false`. The callback remains
 * in the callback list, so when it is enabled again it will execute in the same
 * relative order.
 *
 * @note Disabling an unregistered callback will trigger an assertion error.
 */
void panda_disable_callback(void *plugin, panda_cb_type type, panda_cb cb) {
    bool found = false;
    if (panda_cbs[type] != NULL) {
        for (panda_cb_list *plist = panda_cbs[type]; plist != NULL; plist = plist->next) {
            if (plist->owner == plugin && (plist->entry.cbaddr) == cb.cbaddr) {
                found = true;
                plist->enabled = false;

                // break out of the loop - the same plugin can register the same callback only once
                break;
            }
        }
    }
    // no callback found to disable
    assert(found);
}

/**
 * @brief Enables the execution of the specified callback.
 *
 * This is done by setting the `enabled` flag to `true`. After enabling the
 * callback, it will execute in the same relative order as before having it
 * disabled.
 *
 * @note Enabling an unregistered callback will trigger an assertion error.
 */
void panda_enable_callback(void *plugin, panda_cb_type type, panda_cb cb) {
    bool found = false;
    if (panda_cbs[type] != NULL) {
        for (panda_cb_list *plist = panda_cbs[type]; plist != NULL; plist = plist->next) {
            if (plist->owner == plugin && (plist->entry.cbaddr) == cb.cbaddr) {
                found = true;
                plist->enabled = true;

                // break out of the loop - the same plugin can register the same callback only once
                break;
            }
        }
    }
    // no callback found to enable
    assert(found);
}

/**
 * @brief Unregisters all callbacks owned by this plugin.
 *
 * The register callbacks are removed from their respective callback lists.
 * This means that if they are registered again, their execution order may be
 * different.
 */
void panda_unregister_callbacks(void *plugin) {
    for (int i = 0; i < PANDA_CB_LAST; i++) {
        panda_cb_list *plist;
        plist = panda_cbs[i];
        bool done = false;
        panda_cb_list *plist_head = plist;
        while (!done && plist != NULL) {
            panda_cb_list *plist_next = plist->next;
            if (plist->owner == plugin) {
                // delete this entry -- it belongs to our plugin
                panda_cb_list *del_plist = plist;
                if (plist->next == NULL && plist->prev == NULL) {
                    // its the only thing in the list -- list is now empty
                    plist_head = NULL;
                }
                else {
                    // Unlink this entry
                    if (plist->prev) plist->prev->next = plist->next;
                    if (plist->next) plist->next->prev = plist->prev;
                    // new head
                    if (plist == plist_head) plist_head = plist->next;
                }
                // Free the entry we just unlinked
                g_free(del_plist);
                // there should only be one callback in list for this plugin so done
                done = true;
            }
            plist = plist_next;
        }
        // update head
        panda_cbs[i] = plist_head;
    }
}

/**
 * @brief Enables the specified plugin.
 *
 * This works by enabling all the callbacks previously registered by
 * the plugin. This means that when execution order of the callbacks
 * is preserved.
 */
void panda_enable_plugin(void *plugin) {
    for (int i = 0; i < PANDA_CB_LAST; i++) {
        panda_cb_list *plist;
        plist = panda_cbs[i];
        while(plist != NULL) {
            if (plist->owner == plugin) {
                plist->enabled = true;
            }
            plist = plist->next;
        }
    }
}

/**
 * @brief Disables the specified plugin.
 *
 * This works by disabling all the callbacks registered by the plugin.
 * This means that when the plugin is re-enabled, the callback order
 * is preserved.
 */
void panda_disable_plugin(void *plugin) {
    for (int i = 0; i < PANDA_CB_LAST; i++) {
        panda_cb_list *plist;
        plist = panda_cbs[i];
        while(plist != NULL) {
            if (plist->owner == plugin) {
                plist->enabled = false;
            }
            plist = plist->next;
        }
    }
}

/**
 * @brief Allows to navigate the callback linked list skipping disabled callbacks.
 */
panda_cb_list* panda_cb_list_next(panda_cb_list* plist) {
    for (panda_cb_list* node = plist->next; plist != NULL; plist = plist->next) {
        if (!node || node->enabled) return node;
    }
    return NULL;
}

bool panda_flush_tb(void) {
    if(panda_please_flush_tb) {
        panda_please_flush_tb = false;
        return true;
    }
    else return false;
}

void panda_do_flush_tb(void) {
    panda_please_flush_tb = true;
}

void panda_enable_precise_pc(void) {
    panda_update_pc = true;
}

void panda_disable_precise_pc(void) {
    panda_update_pc = false;
}

void panda_enable_memcb(void) {
    panda_use_memcb = true;
}

void panda_disable_memcb(void) {
    panda_use_memcb = false;
}

void panda_enable_tb_chaining(void){
    panda_tb_chaining = true;
}

void panda_disable_tb_chaining(void){
    panda_tb_chaining = false;
}

#ifdef CONFIG_LLVM
void panda_enable_llvm(void){
    panda_do_flush_tb();
    execute_llvm = 1;
    generate_llvm = 1;
    tcg_llvm_ctx = tcg_llvm_initialize();
}

extern CPUState *env;

void panda_disable_llvm(void){
    execute_llvm = 0;
    generate_llvm = 0;
    tcg_llvm_destroy();
    tcg_llvm_ctx = NULL;
}

void panda_enable_llvm_helpers(void){
    init_llvm_helpers();
}

void panda_disable_llvm_helpers(void){
    uninit_llvm_helpers();
}

#endif

void panda_memsavep(FILE *f) {
#ifdef CONFIG_SOFTMMU
    if (!f) return;
    uint8_t mem_buf[TARGET_PAGE_SIZE];
    uint8_t zero_buf[TARGET_PAGE_SIZE];
    memset(zero_buf, 0, TARGET_PAGE_SIZE);
    int res;
    ram_addr_t addr;
    for (addr = 0; addr < ram_size; addr += TARGET_PAGE_SIZE) {
        res = panda_physical_memory_rw(addr, mem_buf, TARGET_PAGE_SIZE, 0);
        if (res == -1) { // I/O. Just fill page with zeroes.
            fwrite(zero_buf, TARGET_PAGE_SIZE, 1, f);
        }
        else {
            fwrite(mem_buf, TARGET_PAGE_SIZE, 1, f);
        }
    }
#endif
}

// Parse out arguments and return them to caller
static panda_arg_list *panda_get_args_internal(const char *plugin_name, bool check_only) {
    panda_arg_list *ret = NULL;
    panda_arg *list = NULL;

    ret = g_new0(panda_arg_list, 1);
    if (ret == NULL) goto fail;

    int i;
    int nargs = 0;
    // one pass to get number of matching args
    for (i = 0; i < panda_argc; i++) {
        if (0 == strncmp(plugin_name, panda_argv[i], strlen(plugin_name))) {
            nargs++;
        }
    }

    if (nargs != 0) {
        ret->nargs = nargs;
        list = (panda_arg *) g_malloc(sizeof(panda_arg)*nargs);
        if (list == NULL) goto fail;
    }

    // Put plugin name in here so we can use it
    ret->plugin_name = g_strdup(plugin_name);

    // second pass to copy and parse each arg into key/value
    int ret_idx = 0;
    for (i = 0; i < panda_argc; i++) {
        if (0 == strncmp(plugin_name, panda_argv[i], strlen(plugin_name))) {
            list[ret_idx].argptr = g_strdup(panda_argv[i]);
            bool found_colon = false;
            bool found_equals = false;
            char *p;
            int j;
            for (p = list[ret_idx].argptr, j = 0;
                    *p != '\0' && j < 256; p++, j++) {
                if (*p == ':') {
                    *p = '\0';
                    list[ret_idx].key = p+1;
                    found_colon = true;
                }
                else if (*p == '=') {
                    *p = '\0';
                    list[ret_idx].value = p+1;
                    found_equals = true;
                    break;
                }
            }
            if (!found_colon) {
                // malformed argument
                goto fail;
            }
            if (!found_equals) {
                list[ret_idx].value = (char *) "";
            }
            ret_idx++;
        }
    }

    ret->list = list;

    for (i = 0; i < ret->nargs; i++) {
        if (strcmp(ret->list[i].key, "help") == 0) {
            panda_help_wanted = true;
            panda_abort_requested = true;
        }
    }
    
    if (check_only) {
        panda_free_args(ret);
        ret = NULL;
    }

    return ret;

fail:
    if (ret != NULL) g_free(ret);
    if (list != NULL) g_free(list);
    return NULL;
}

static void panda_args_set_help_wanted(const char *plugin_name) {
    panda_get_args_internal(plugin_name, true);
}

panda_arg_list *panda_get_args(const char *plugin_name) {
    return panda_get_args_internal(plugin_name, false);
}

static bool panda_parse_bool_internal(panda_arg_list *args, const char *argname, const char *help, bool required) {
    gchar *val = NULL;
    if (panda_help_wanted) goto help;
    if (!args) goto error_handling;
    for (int i = 0; i < args->nargs; i++) {
        if (g_ascii_strcasecmp(args->list[i].key, argname) == 0) {
            val = args->list[i].value;
            for (const gchar **vp=panda_bool_true_strings; *vp != NULL; vp++) {
                if (g_ascii_strcasecmp(*vp, val) == 0) return true;
            }
            for (const gchar **vp=panda_bool_false_strings; *vp != NULL; vp++) {
                if (g_ascii_strcasecmp(*vp, val) == 0) return false;
            }

            // argument name matched
            break;
        }
    }

error_handling:
    if (val != NULL) { // value provided but not in the list of accepted values
        fprintf(stderr, PANDA_MSG_FMT "FAILED to parse value \"%s\" for bool argument \"%s\"\n", PANDA_CORE_NAME, val, argname);
        panda_plugin_load_failed = true;
    }
    else if (required) { // value not provided but required
        fprintf(stderr, PANDA_MSG_FMT "ERROR finding required bool argument \"%s\"\n", PANDA_CORE_NAME, argname);
        fprintf(stderr, PANDA_MSG_FMT "help for \"%s\": %s\n", PANDA_CORE_NAME, argname, help);
        panda_plugin_load_failed = true;
    }
help:
    if (panda_help_wanted) {
        fprintf(stderr, "%-20s%-24sOptional        %s (default=true)\n", args->plugin_name, argname, help);
    }

    // not found
    return false;
}

bool panda_parse_bool_req(panda_arg_list *args, const char *argname, const char *help) {
    return panda_parse_bool_internal(args, argname, help, true);
}

bool panda_parse_bool_opt(panda_arg_list *args, const char *argname, const char *help) {
    return panda_parse_bool_internal(args, argname, help, false);
}

bool panda_parse_bool(panda_arg_list *args, const char *argname) {
    return panda_parse_bool_internal(args, argname, "Undocumented option. Complain to the developer!", false);
}

static target_ulong panda_parse_ulong_internal(panda_arg_list *args, const char *argname, target_ulong defval, const char *help, bool required) {
    if (panda_help_wanted) goto help;
    if (!args) goto error_handling;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtoul(args->list[i].value, NULL, 0);
        }
    }

error_handling:
    if (required) {
        fprintf(stderr, "ERROR: plugin required ulong argument \"%s\" but you did not provide it\n", argname);
        fprintf(stderr, "Help for \"%s\": %s\n", argname, help);
        panda_plugin_load_failed = true;
    }
help:
    if (panda_help_wanted) {
        if (required) fprintf(stderr, "%-20s%-24sRequired        %s\n", args->plugin_name, argname, help);
        else fprintf(stderr, "%-20s%-24sOptional        %s (default=" TARGET_FMT_ld ")\n", args->plugin_name, argname, help, defval);
    }

    return defval;
}

target_ulong panda_parse_ulong_req(panda_arg_list *args, const char *argname, const char *help) {
    return panda_parse_ulong_internal(args, argname, 0, help, true);
}

target_ulong panda_parse_ulong_opt(panda_arg_list *args, const char *argname, target_ulong defval, const char *help) {
    return panda_parse_ulong_internal(args, argname, defval, help, false);
}

target_ulong panda_parse_ulong(panda_arg_list *args, const char *argname, target_ulong defval) {
    return panda_parse_ulong_internal(args, argname, defval, "Undocumented option. Complain to the developer!", false);
}

static uint32_t panda_parse_uint32_internal(panda_arg_list *args, const char *argname, uint32_t defval, const char *help, bool required) {
    if (panda_help_wanted) goto help;
    if (!args) goto error_handling;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtoull(args->list[i].value, NULL, 0);
        }
    }

error_handling:
    if (required) {
        fprintf(stderr, "ERROR: plugin required uint32 argument \"%s\" but you did not provide it\n", argname);
        fprintf(stderr, "Help for \"%s\": %s\n", argname, help);
        panda_plugin_load_failed = true;
    }
help:
    if (panda_help_wanted) {
        if (required) fprintf(stderr, "%-20s%-24sRequired        %s\n", args->plugin_name, argname, help);
        else fprintf(stderr, "%-20s%-24sOptional        %s (default=%d)\n", args->plugin_name, argname, help, defval);
    }

    return defval;
}

uint32_t panda_parse_uint32_req(panda_arg_list *args, const char *argname, const char *help) {
    return panda_parse_uint32_internal(args, argname, 0, help, true);
}

uint32_t panda_parse_uint32_opt(panda_arg_list *args, const char *argname, uint32_t defval, const char *help) {
    return panda_parse_uint32_internal(args, argname, defval, help, false);
}

uint32_t panda_parse_uint32(panda_arg_list *args, const char *argname, uint32_t defval) {
    return panda_parse_uint32_internal(args, argname, defval, "Undocumented option. Complain to the developer!", false);
}

static uint64_t panda_parse_uint64_internal(panda_arg_list *args, const char *argname, uint64_t defval, const char *help, bool required) {
    if (panda_help_wanted) goto help;
    if (!args) goto error_handling;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtoull(args->list[i].value, NULL, 0);
        }
    }

error_handling:
    if (required) {
        fprintf(stderr, "ERROR: plugin required uint64 argument \"%s\" but you did not provide it\n", argname);
        fprintf(stderr, "Help for \"%s\": %s\n", argname, help);
        panda_plugin_load_failed = true;
    }
help:
    if (panda_help_wanted) {
        if (required) fprintf(stderr, "%-20s%-24sRequired        %s)\n", args->plugin_name, argname, help);
        else fprintf(stderr, "%-20s%-24sOptional        %s (default=%" PRId64 ")\n", args->plugin_name, argname, help, defval);
    }

    return defval;
}

uint64_t panda_parse_uint64_req(panda_arg_list *args, const char *argname, const char *help) {
    return panda_parse_uint64_internal(args, argname, 0, help, true);
}

uint64_t panda_parse_uint64_opt(panda_arg_list *args, const char *argname, uint64_t defval, const char *help) {
    return panda_parse_uint64_internal(args, argname, defval, help, false);
}

uint64_t panda_parse_uint64(panda_arg_list *args, const char *argname, uint64_t defval) {
    return panda_parse_uint64_internal(args, argname, defval, "Undocumented option. Complain to the developer!", false);
}

static double panda_parse_double_internal(panda_arg_list *args, const char *argname, double defval, const char *help, bool required) {
    if (panda_help_wanted) goto help;
    if (!args) goto error_handling;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtod(args->list[i].value, NULL);
        }
    }

error_handling:
    if (required) {
        fprintf(stderr, "ERROR: plugin required double argument \"%s\" but you did not provide it\n", argname);
        fprintf(stderr, "Help for \"%s\": %s\n", argname, help);
        panda_plugin_load_failed = true;
    }
help:
    if (panda_help_wanted) {
        if (required) fprintf(stderr, "%-20s%-24sRequired        %s\n", args->plugin_name, argname, help);
        else fprintf(stderr, "%-20s%-24sOptional        %s (default=%f)\n", args->plugin_name, argname, help, defval);
    }

    return defval;
}

double panda_parse_double_req(panda_arg_list *args, const char *argname, const char *help) {
    return panda_parse_double_internal(args, argname, 0, help, true);
}

double panda_parse_double_opt(panda_arg_list *args, const char *argname, double defval, const char *help) {
    return panda_parse_double_internal(args, argname, defval, help, false);
}

double panda_parse_double(panda_arg_list *args, const char *argname, double defval) {
    return panda_parse_double_internal(args, argname, defval, "Undocumented option. Complain to the developer!", false);
}

char** str_split(char* a_str, const char a_delim)  {
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;
    /* Count how many elements will be extracted. */
    while (*tmp) {
        if (a_delim == *tmp) {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }
    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);
    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;
    result = malloc(sizeof(char*) * count);
    if (result) {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);
        while (token)  {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }
    return result;
}


// Returns pointer to string inside arg list, freed when list is freed.
static const char *panda_parse_string_internal(panda_arg_list *args, const char *argname, const char *defval, const char *help, bool required) {
    if (panda_help_wanted) goto help;
    if (!args) goto error_handling;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return args->list[i].value;
        }
    }

error_handling:
    if (required) {
        fprintf(stderr, "ERROR: plugin required string argument \"%s\" but you did not provide it\n", argname);
        fprintf(stderr, "Help for \"%s\": %s\n", argname, help);
        panda_plugin_load_failed = true;
    }
help:
    if (panda_help_wanted) {
        if (required) fprintf(stderr, "%-20s%-24sRequired        %s\n", args->plugin_name, argname, help);
        else fprintf(stderr, "%-20s%-24sOptional        %s (default=\"%s\")\n", args->plugin_name, argname, help, defval);
    }

    return defval;
}

const char *panda_parse_string_req(panda_arg_list *args, const char *argname, const char *help) {
    return panda_parse_string_internal(args, argname, "", help, true);
}

const char *panda_parse_string_opt(panda_arg_list *args, const char *argname, const char *defval, const char *help) {
    return panda_parse_string_internal(args, argname, defval, help, false);
}

const char *panda_parse_string(panda_arg_list *args, const char *argname, const char *defval) {
    return panda_parse_string_internal(args, argname, defval, "Undocumented option. Complain to the developer!", false);
}

// Free a list of parsed arguments
void panda_free_args(panda_arg_list *args) {
    int i;
    if (!args) return;
    for (i = 0; i < args->nargs; i++) {
        g_free(args->list[i].argptr);
    }
    g_free(args->plugin_name);
    g_free(args);
}

#ifdef CONFIG_SOFTMMU

// QMP


void qmp_load_plugin(bool has_file_name, const char *file_name, const char *plugin_name, bool has_plugin_args, const char *plugin_args, Error **errp){

    if(!has_file_name)
        file_name = panda_plugin_path(plugin_name);

    if (has_plugin_args){
        gchar *args = g_strdup(plugin_args);
        char *args_start = args;
        char *args_end = args;

        while (args_end != NULL) {
            args_end = strchr(args_start, ',');
            if (args_end != NULL) *args_end = '\0';

            // panda_add_arg() currently always return true
            assert(panda_add_arg(plugin_name, args_start));

            args_start = args_end + 1;
        }

        g_free(args);
    }

    if(!panda_load_plugin(file_name, plugin_name)) {
        // TODO: do something with errp here?
    }

    if(!has_file_name)
        g_free((char *)file_name);
}

void qmp_unload_plugin(int64_t index, Error **errp) {
    if (index >= nb_panda_plugins || index < 0) {
        // TODO: errp
    } else {
        panda_unload_plugin_idx(index);
    }
}

PandaPluginInfoList *qmp_list_plugins(Error **errp) {
    PandaPluginInfoList *head = NULL;
    int i;

    for (i = 0; i < nb_panda_plugins; i++) {
        PandaPluginInfoList *list_item = g_new0(typeof(*list_item), 1);
        PandaPluginInfo *plugin_item = g_new0(typeof(*plugin_item), 1);

        plugin_item->index = i;
        plugin_item->name = g_strdup(panda_plugins[i].name);
        plugin_item->address = (unsigned long) panda_plugins[i].plugin;

        list_item->value = plugin_item;
        list_item->next = head;
        head = list_item;
    }
    return head;
}

void qmp_plugin_cmd(const char * cmd, Error **errp) {
    
}

void hmp_panda_plugin_cmd(Monitor *mon, const QDict *qdict);


// HMP
void hmp_panda_load_plugin(Monitor *mon, const QDict *qdict) {
    Error *err;
    const char *file_name   = qdict_get_try_str(qdict, "file_name");
    const char *plugin_name = qdict_get_try_str(qdict, "plugin_name");
    const char *plugin_args = qdict_get_try_str(qdict, "plugin_args");
    bool has_file_name   = file_name ? true : false;
    bool has_plugin_args = plugin_args ? true : false;
    qmp_load_plugin(has_file_name, file_name, plugin_name, has_plugin_args, plugin_args, &err);
}

void hmp_panda_unload_plugin(Monitor *mon, const QDict *qdict) {
    Error *err;
    const int index = qdict_get_try_int(qdict, "index", -1);
    qmp_unload_plugin(index, &err);
}

void hmp_panda_list_plugins(Monitor *mon, const QDict *qdict) {
    Error *err;
    PandaPluginInfoList *plugin_item = qmp_list_plugins(&err);
    monitor_printf(mon, "idx\t%-20s\taddr\n", "name");
    while (plugin_item != NULL){
        monitor_printf(mon, "%ld\t%-20s\t%lx\n", plugin_item->value->index, 
                        plugin_item->value->name, plugin_item->value->address);
        plugin_item = plugin_item->next;

    }
}

void hmp_panda_plugin_cmd(Monitor *mon, const QDict *qdict) {
    panda_cb_list *plist;
    const char *cmd = qdict_get_try_str(qdict, "cmd");
    for(plist = panda_cbs[PANDA_CB_MONITOR]; plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.monitor(mon, cmd);
    }
}

#endif // CONFIG_SOFTMMU
