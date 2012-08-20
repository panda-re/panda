#include "panda_plugin.h"
#include <dlfcn.h>

// Array of pointers to PANDA callback lists, one per callback type
panda_cb_list *panda_cbs[PANDA_CB_LAST];

void *panda_plugins[16];
int nb_panda_plugins;

void * load_panda_plugin(const char *filename) {
    void *plugin = dlopen(filename, RTLD_NOW);
    if(!plugin) {
        fprintf(stderr, "Failed to load %s: %s\n", filename, dlerror());
        return NULL;
    }
    bool (*init_fn)(void) = dlsym(plugin, "init_plugin");
    if(!init_fn) {
        fprintf(stderr, "Couldn't get symbol %s: %s\n", "init_plugin", dlerror());
        dlclose(plugin);
        return NULL;
    }
    if(init_fn()) {
        return plugin;
    }
    else {
        dlclose(plugin);
        return NULL;
    }
}

void unload_panda_plugin(void *plugin) {
    void (*uninit_fn)(void) = dlsym(plugin, "uninit_plugin");
    if(!uninit_fn) {
        fprintf(stderr, "Couldn't get symbol %s: %s\n", "uninit_plugin", dlerror());
    }
    uninit_fn();
    dlclose(plugin);
}

void register_panda_callback(panda_cb_type type, panda_cb cb) {
    panda_cb_list *new_list = g_new0(panda_cb_list,1);
    new_list->entry = cb;
    if(panda_cbs[type] != NULL) {
        new_list->next = panda_cbs[type];
    }
    panda_cbs[type] = new_list;
}

