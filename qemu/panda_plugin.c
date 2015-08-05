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
#include "config.h"
#include "panda_plugin.h"
#include "qemu-common.h"
#include "qdict.h"
#include "qmp-commands.h"
#include "hmp.h"
#include "error.h"

#include <libgen.h>

#ifdef CONFIG_LLVM
#include "panda/panda_helper_call_morph.h"
#include "tcg.h"
#include "tcg-llvm.h"
#endif

#include <dlfcn.h>
#include <string.h>


// WARNING: this is all gloriously un-thread-safe

// Array of pointers to PANDA callback lists, one per callback type
panda_cb_list *panda_cbs[PANDA_CB_LAST];

// Storage for command line options
char panda_argv[MAX_PANDA_PLUGIN_ARGS][256];
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



bool panda_add_arg(const char *arg, int arglen) {
    if (arglen > 255) return false;
    strncpy(panda_argv[panda_argc++], arg, 255);
    return true;
}

bool panda_load_plugin(const char *filename) {
    // don't load the same plugin twice
    uint32_t i;
    for (i=0; i<nb_panda_plugins_loaded; i++) {
        if (0 == (strcmp(filename, panda_plugins_loaded[i]))) {
            printf ("panda_load_plugin: %s already loaded\n", filename);
            return 1;
        }
    }    
    panda_plugins_loaded[nb_panda_plugins_loaded] = strdup(filename);
    nb_panda_plugins_loaded ++;
    printf ("loading %s\n", filename);
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
    if(init_fn(plugin)) {
        panda_plugins[nb_panda_plugins].plugin = plugin;
        strncpy(panda_plugins[nb_panda_plugins].name, basename((char *) filename), 256);
        nb_panda_plugins++;
        fprintf (stderr, "Success\n");
        return true;
    }
    else {
        dlclose(plugin);
        fprintf (stderr, "Fail. init_fn returned 0\n");
        return false;
    }
}

extern const char *qemu_file;

// translate plugin name into path to .so
char *panda_plugin_path(const char *plugin_name) {    
    char *plugin_path = g_malloc0(1024);
    char *plugin_dir = getenv("PANDA_PLUGIN_DIR");
    if (plugin_dir != NULL) {
        snprintf(plugin_path, 1024, "%s/panda_%s.so", plugin_dir, plugin_name);
    } else {
        char *dir = strdup(qemu_file);
        dir = dirname( (char *) dir);
        snprintf(plugin_path, 1024, "%s/panda_plugins/panda_%s.so", dir, plugin_name);
    }
    return plugin_path;
}


void panda_require(const char *plugin_name) {
    printf ("panda_require: %s\n", plugin_name);
    // translate plugin name into a path to .so
    char *plugin_path = panda_plugin_path(plugin_name);
    // load plugin same as in vl.c
    if (!panda_load_plugin(plugin_path)) {
        fprintf(stderr, "panda_require: FAIL: Unable to load plugin `%s' `%s'\n", plugin_name, plugin_path);
        abort();
    }
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

void panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb) {
    panda_cb_list *new_list = g_new0(panda_cb_list,1);
    new_list->entry = cb;
    new_list->owner = plugin;
    new_list->prev = NULL;
    new_list->next = NULL;
    new_list->enabled = true;
    if(panda_cbs[type] != NULL) {
        new_list->next = panda_cbs[type];
        panda_cbs[type]->prev = new_list;
    }
    panda_cbs[type] = new_list;
}

void panda_unregister_callbacks(void *plugin) {
    // Remove callbacks
    int i;
    for (i = 0; i < PANDA_CB_LAST; i++) {
        panda_cb_list *plist;
        plist = panda_cbs[i];
        while(plist != NULL) {
            if (plist->owner == plugin) {
                panda_cb_list *old_plist = plist;
                // Unlink
                if (plist->prev)
                    plist->prev->next = plist->next;
                if (plist->next)
                    plist->next->prev = plist->prev;
                if (!plist->prev && !plist->next){
                    // List is now empty
                    panda_cbs[i] = NULL;
                }
                // Advance the pointer
                plist = plist->next;
                // Free the entry we just unlinked
                g_free(old_plist);
            }
            else {
                plist = plist->next;
            }
        }
    }
}

void panda_enable_plugin(void *plugin) {
    int i;
    for (i = 0; i < PANDA_CB_LAST; i++) {
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

void panda_disable_plugin(void *plugin) {
    int i;
    for (i = 0; i < PANDA_CB_LAST; i++) {
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

panda_cb_list* panda_cb_list_next(panda_cb_list* plist) {
    // Allows to navigate the callback linked list skipping disabled callbacks
    panda_cb_list* node = plist->next;
    if (node == NULL) {
        return node;
    }

    if (node->enabled) {
        return node;
    } else {
        return panda_cb_list_next(node);
    }
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
    tb_flush(env);
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
panda_arg_list *panda_get_args(const char *plugin_name) {
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

    if (nargs == 0) goto fail;

    ret->nargs = nargs;
    list = (panda_arg *) g_malloc(sizeof(panda_arg)*nargs);
    if (list == NULL) goto fail;

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

    return ret;

fail:
    if (ret != NULL) g_free(ret);
    if (list != NULL) g_free(list);
    return NULL;
}

bool panda_parse_bool(panda_arg_list *args, const char *argname) {
    if (!args) return false;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            char *val = args->list[i].value;
            if (strcmp("false", val) == 0 || strcmp("no", val) == 0) {
                return false;
            } else {
                return true;
            }
        }
    }
    // not found
    return false;
}

target_ulong panda_parse_ulong(panda_arg_list *args, const char *argname, target_ulong defval) {
    if (!args) return defval;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtoul(args->list[i].value, NULL, 0);
        }
    }
    return defval;
}

uint32_t panda_parse_uint32(panda_arg_list *args, const char *argname, uint32_t defval) {
    if (!args) return defval;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtoull(args->list[i].value, NULL, 0);
        }
    }
    return defval;
}


uint64_t panda_parse_uint64(panda_arg_list *args, const char *argname, uint64_t defval) {
    if (!args) return defval;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtoull(args->list[i].value, NULL, 0);
        }
    }
    return defval;
}

double panda_parse_double(panda_arg_list *args, const char *argname, double defval) {
    if (!args) return defval;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return strtod(args->list[i].value, NULL);
        }
    }
    return defval;
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
const char *panda_parse_string(panda_arg_list *args, const char *argname, const char *defval) {
    if (!args) return defval;
    int i;
    for (i = 0; i < args->nargs; i++) {
        if (strcmp(args->list[i].key, argname) == 0) {
            return args->list[i].value;
        }
    }
    return defval;
}

// Free a list of parsed arguments
void panda_free_args(panda_arg_list *args) {
    int i;
    if (!args) return;
    for (i = 0; i < args->nargs; i++) {
        g_free(args->list[i].argptr);
    }
    g_free(args);
}

#ifdef CONFIG_SOFTMMU

// QMP

void qmp_load_plugin(const char *filename, Error **errp) {
    if(!panda_load_plugin(filename)) {
        // TODO: do something with errp here?
    }
}

void qmp_unload_plugin(int64_t index, Error **errp) {
    if (index >= nb_panda_plugins || index < 0) {
        // TODO: errp
    } else {
        panda_unload_plugin_idx(index);
    }
}

void qmp_list_plugins(Error **errp) {
    
}

void qmp_plugin_cmd(const char * cmd, Error **errp) {
    
}

// HMP
void hmp_panda_load_plugin(Monitor *mon, const QDict *qdict) {
    Error *err;
    const char *filename = qdict_get_try_str(qdict, "filename");
    qmp_load_plugin(filename, &err);
}

void hmp_panda_unload_plugin(Monitor *mon, const QDict *qdict) {
    Error *err;
    const int index = qdict_get_try_int(qdict, "index", -1);
    qmp_unload_plugin(index, &err);
}

void hmp_panda_list_plugins(Monitor *mon, const QDict *qdict) {
    Error *err;
    int i;
    monitor_printf(mon, "idx\t%-20s\taddr\n", "name");
    for (i = 0; i < nb_panda_plugins; i++) {
        monitor_printf(mon, "%d\t%-20s\t%p\n", i, panda_plugins[i].name, panda_plugins[i].plugin);
    }
    qmp_list_plugins(&err);
}

void hmp_panda_plugin_cmd(Monitor *mon, const QDict *qdict) {
    panda_cb_list *plist;
    const char *cmd = qdict_get_try_str(qdict, "cmd");
    for(plist = panda_cbs[PANDA_CB_MONITOR]; plist != NULL; plist = panda_cb_list_next(plist)) {
        plist->entry.monitor(mon, cmd);
    }
}

#endif // CONFIG_SOFTMMU
