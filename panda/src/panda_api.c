#include <assert.h>

#include "vl.h"
#include "panda/panda_api.h"
#include "panda/plugin.h"

int panda_virtual_memory_read_external(CPUState *env, target_ulong addr, uint8_t *buf, int len);
int panda_virtual_memory_write_external(CPUState *env, target_ulong addr, uint8_t *buf, int len);
int rr_get_guest_instr_count_external(void);
void qemu_rr_quit_timers(void);
//void qemu_cpu_kick(CPUState *cpu);
void panda_register_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);
target_ulong panda_current_sp_external(CPUState *cpu);
bool panda_in_kernel_external(CPUState *cpu);


int panda_pre(int argc, char **argv, char **envp) {
    return main_aux(argc, argv, envp, PANDA_PRE);
}

int panda_init(int argc, char **argv, char **envp) {
    return main_aux(argc, argv, envp, PANDA_INIT);
}

extern int panda_in_main_loop;

int panda_run(void) {
    qemu_cpu_kick(first_cpu);
    panda_in_main_loop = 1;
    main_loop();
    panda_in_main_loop = 0;
    return 0;
}

int panda_finish(void) {
    return main_aux(0, 0, 0, PANDA_FINISH);
}

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args) {
    for (uint32_t i=0; i<num_args; i++) 
        panda_add_arg(plugin_name, plugin_args[i]);
    char *plugin_path = panda_plugin_path((const char *) plugin_name);
    return panda_load_plugin(plugin_path, plugin_name);
}
void panda_register_callback_helper(void *plugin, panda_cb_type type, panda_cb* cb) {
	panda_cb cb_copy;
	memcpy(&cb_copy,cb, sizeof(panda_cb));
	panda_register_callback(plugin, type, cb_copy);
}

// initiate replay 
int panda_replay(char *replay_name) {
    rr_replay_requested = 1;
    rr_requested_name = strdup(replay_name);
    return 0;
//    return panda_run();
}

int rr_get_guest_instr_count_external(void){
	return rr_get_guest_instr_count();
}

int panda_virtual_memory_read_external(CPUState *env, target_ulong addr, uint8_t *buf, int len){
	return panda_virtual_memory_read(env, addr, buf, len);
}

int panda_virtual_memory_write_external(CPUState *env, target_ulong addr, uint8_t *buf, int len){
	return panda_virtual_memory_write(env, addr, buf, len);
}

bool panda_in_kernel_external(CPUState *cpu){
	return panda_in_kernel(cpu);
}

target_ulong panda_current_sp_external(CPUState *cpu){
	return panda_current_sp(cpu);
}

// we have this temporarily in callbacks.c -> to be moved here
/*
bool panda_load_external_plugin(const char *filename, const char *plugin_name, void *plugin_uuid, void *init_fn_ptr) {
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
    void *plugin = plugin_uuid;//going to be a handle of some sort -> dlopen(filename, RTLD_NOW);
    bool (*init_fn)(void *) = init_fn_ptr; //normally dlsym init_fun

    // Populate basic plugin info *before* calling init_fn.
    // This allows plugins accessing handles of other plugins before
    // initialization completes. E.g. osi does a panda_require("win7x86intro"),
    // and then win7x86intro does a PPP_REG_CB("osi", ...) while initializing.
    panda_plugins[nb_panda_plugins].plugin = plugin;
    if (plugin_name) {
        strncpy(panda_plugins[nb_panda_plugins].name, plugin_name, 256);
    } else {
        char *pn = g_path_get_basename((char *) filename);
        *g_strrstr(pn, HOST_DSOSUF) = '\0';
        strncpy(panda_plugins[nb_panda_plugins].name, pn, 256);
        g_free(pn);
    }
    nb_panda_plugins++;

    // Call init_fn and check status.
    fprintf(stderr, PANDA_MSG_FMT "initializing %s\n", PANDA_CORE_NAME, panda_plugins[nb_panda_plugins-1].name);
    panda_help_wanted = false;
    panda_args_set_help_wanted(plugin_name);
    if (panda_help_wanted) {
        printf("Options for plugin %s:\n", plugin_name);
        fprintf(stderr, "PLUGIN              ARGUMENT                REQUIRED        DESCRIPTION\n");
        fprintf(stderr, "======              ========                ========        ===========\n");
    }
    if(!init_fn(plugin) || panda_plugin_load_failed) {
        return false;
    }
    return true;
}*/
