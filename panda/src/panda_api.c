#include <assert.h>


#include "vl.h"
#include "panda/panda_api.h"
#include "panda/plugin.h"

extern int load_vmstate(char *name);

int panda_virtual_memory_read_external(CPUState *env, target_ulong addr, uint8_t *buf, int len);
int panda_virtual_memory_write_external(CPUState *env, target_ulong addr, uint8_t *buf, int len);
int rr_get_guest_instr_count_external(void);
void qemu_rr_quit_timers(void);
//void qemu_cpu_kick(CPUState *cpu);
void panda_register_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);
target_ulong panda_current_sp_external(CPUState *cpu);
bool panda_in_kernel_external(CPUState *cpu);

int save_vmstate_nomon(const char *name);


// just call main_aux and return IMMEDIATELY
// after this we will be able to register plugins in python
int panda_pre(int argc, char **argv, char **envp) {
    return main_aux(argc, argv, envp, PANDA_PRE);
}

// call main_aux and run everything up to and including panda_callbacks_after_machine_init
int panda_init(int argc, char **argv, char **envp) {
    return main_aux(argc, argv, envp, PANDA_INIT);
}

extern int panda_in_main_loop;
extern bool panda_exit_loop;
extern bool panda_stopped;

extern bool panda_revert_requested;
extern char *panda_revert_name;

extern bool panda_snap_requested;
extern char *panda_snap_name;

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

void panda_exit_emul_loop(void) {
    printf ("panda_api: exit_emul_loop\n");
    panda_exit_loop = true;
}

int do_vm_stop(int state);

void panda_stop(void) {
    printf ("panda_api: stop cpu\n");
    //  panda_stopped = true;
    do_vm_stop(4 /* RUN_STATE_PAUSED*/ );
}

void vm_start(void);

void panda_cont(void) {
    printf ("panda_api: cont cpu\n");
    panda_stopped = false;
    vm_start();
} 

int panda_revert(char *snapshot_name) {
/*
    panda_exit_loop = true;
    panda_revert_requested = true;
    panda_revert_name = strdup(snapshot_name);
    return 1;
*/
    printf ("In panda_revert snapshot=%s\n", snapshot_name);
    int ret = load_vmstate(snapshot_name);
    printf ("Got back grom load_vmstate ret=%d\n", ret);
    return ret;
}

int panda_snap(char *snapshot_name) {
/*
    panda_exit_loop = true;
    panda_snap_requested = true;
    panda_snap_name = strdup(snapshot_name);
    return 1;
*/
    printf("panda_snap %s\n", snapshot_name);
    return save_vmstate_nomon(snapshot_name);  
}



int delvm_name(char *name);

int panda_delvm(char *snapshot_name) {
/*
    panda_exit_loop = true;
    panda_delvm_name_requested = true;
    panda_delvm_name_name = strdup(name);
    return 1;
*/
    printf ("In panda_delvm snapshot=%s\n", snapshot_name);
    delvm_name(snapshot_name);
    return 1;
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
