#ifndef __PANDA_PLUGIN_MGMT_H__
#define __PANDA_PLUGIN_MGMT_H__

//  Manage plugins (load, enable, disable, etc).
//  and callbacks (regster, unregister, etc) .

// NOTE: Pls read README before editing!

// Doubly linked list that stores a callback, along with its owner
typedef struct _panda_cb_list panda_cb_list;
struct _panda_cb_list {
    panda_cb entry;
    void *owner;
    panda_cb_list *next;
    panda_cb_list *prev;
    bool enabled;
};

// Structure to store metadata about a plugin
typedef struct panda_plugin {
    char name[256];     // Currently basename(filename)
    void *plugin;       // Handle to the plugin (for use with dlsym())
} panda_plugin;

extern bool panda_plugins_to_unload[MAX_PANDA_PLUGINS];
extern bool panda_plugin_to_unload;

extern panda_cb_list *panda_cbs[PANDA_CB_LAST];

// plugin mgmt
bool panda_load_external_plugin(const char *filename, const char *plugin_name, 
                                void *plugin_uuid, void *init_fn_ptr);
bool panda_load_plugin(const char *filename, const char *plugin_name);
char *panda_plugin_path(const char *name);
void panda_require(const char *plugin_name);
void panda_do_unload_plugin(int index);
void panda_unload_plugin(void* plugin);
void panda_unload_plugin_idx(int idx);
void panda_unload_plugins(void);
void *panda_get_plugin_by_name(const char *name);
void panda_unload_plugin_by_name(const char* name);
void panda_enable_plugin(void *plugin);
void panda_disable_plugin(void *plugin);

// callback mgmt
void panda_register_callback(void *plugin, panda_cb_type type, panda_cb cb);
void panda_disable_callback(void *plugin, panda_cb_type type, panda_cb cb);
void panda_enable_callback(void *plugin, panda_cb_type type, panda_cb cb);
void panda_unregister_callbacks(void *plugin);
panda_cb_list* panda_cb_list_next(panda_cb_list* plist);

#endif
