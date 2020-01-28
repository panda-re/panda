#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

#include "vl.h"
#include "panda/plugin.h"
#include "panda/panda_api.h"
#include "panda/common.h"
#include "sysemu/sysemu.h"

// for map_memory
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "qapi/error.h"
#include "migration/vmstate.h"

// call main_aux and run everything up to and including panda_callbacks_after_machine_init
int panda_init(int argc, char **argv, char **envp) {
    return main_aux(argc, argv, envp, PANDA_INIT);
}

extern void pandalog_cc_init_write(const char * fname);
extern int panda_in_main_loop;

// vl.c
extern char *panda_snap_name;
extern bool panda_library_mode;
extern bool panda_aborted;

int panda_run(void) {
    assert(first_cpu != NULL); // If this fails, it's likely because machine init was wrong (no CPU was created)
    qemu_cpu_kick(first_cpu);
    panda_in_main_loop = 1;
    main_loop();
    panda_in_main_loop = 0;
    return 0;
}

void panda_set_library_mode(bool value) {
    // XXX: This should probably be done via preprocessor macros instead
    panda_library_mode = value;
};

extern int do_vm_stop(int state);

void panda_stop(int code) {
    // default of 4 = run_state_paused
    do_vm_stop(code);
}

void panda_cont(void) {
//    printf ("panda_api: cont cpu\n");
    panda_exit_loop = false; // is this unnecessary?
    vm_start();
} 

int panda_delvm(char *snapshot_name) {
    delvm_name(snapshot_name);
    return 1;
}

void panda_start_pandalog(const char * name) {
    pandalog = 1;
    pandalog_cc_init_write(name);
    printf ("pandalogging to [%s]\n", name);
}

int panda_revert(char *snapshot_name) {
    int ret = load_vmstate(snapshot_name);
//    printf ("Got back load_vmstate ret=%d\n", ret);
    return ret;
}

void panda_reset(void) {
    qemu_system_reset_request();
}

int panda_snap(char *snapshot_name) {
    return save_vmstate(NULL, snapshot_name);
}

int panda_finish(void) {
    return main_aux(0, 0, 0, PANDA_FINISH);
}

bool panda_was_aborted(void) {
  return panda_aborted;
}

extern const char *qemu_file;

void panda_set_qemu_path(char* filepath) {
    qemu_file=filepath;
}

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args) {
    for (uint32_t i=0; i<num_args; i++)
        panda_add_arg(plugin_name, plugin_args[i]);
    char *plugin_path = panda_plugin_path((const char *) plugin_name);
    return panda_load_plugin(plugin_path, plugin_name);
}


// panda_cb is defined in callbacks/cb-defs.h
void panda_register_callback_helper(void *plugin, panda_cb_type type, panda_cb* cb) {
	panda_cb cb_copy;
	memcpy(&cb_copy,cb, sizeof(panda_cb));
	panda_register_callback(plugin, type, cb_copy);
}

void panda_enable_callback_helper(void *plugin, panda_cb_type type, panda_cb* cb) {
	panda_cb cb_copy;
	memcpy(&cb_copy,cb, sizeof(panda_cb));
	panda_enable_callback(plugin, type, cb_copy);
}

void panda_disable_callback_helper(void *plugin, panda_cb_type type, panda_cb* cb) {
	panda_cb cb_copy;
	memcpy(&cb_copy,cb, sizeof(panda_cb));
	panda_disable_callback(plugin, type, cb_copy);
}

//int panda_replay(char *replay_name) -> Now use panda_replay_being(char * replay_name)

int rr_get_guest_instr_count_external(void){
	return rr_get_guest_instr_count();
}

// XXX: why do we have these as _external wrappers instead of just using the real fns?
int panda_virtual_memory_read_external(CPUState *env, target_ulong addr, char *buf, int len){
	return panda_virtual_memory_read(env, addr, (uint8_t*) buf, len);
}

int panda_virtual_memory_write_external(CPUState *env, target_ulong addr, char *buf, int len){
	return panda_virtual_memory_write(env, addr, (uint8_t*) buf, len);
}

int panda_physical_memory_read_external(hwaddr addr, uint8_t *buf, int len){
	return panda_physical_memory_rw(addr, buf, len, 0);
}

int panda_physical_memory_write_external(hwaddr addr, uint8_t *buf, int len){
	return panda_physical_memory_rw(addr,buf,len, 1);
}

bool panda_in_kernel_external(CPUState *cpu){
	return panda_in_kernel(cpu);
}

target_ulong panda_current_sp_external(CPUState *cpu){
	return panda_current_sp(cpu);
}

target_ulong panda_current_sp_masked_pagesize_external(CPUState *cpu, target_ulong mask){
	return (panda_current_sp(cpu) & (~(mask+mask-1)));
}

target_ulong panda_virt_to_phys_external(CPUState *cpu, target_ulong virt_addr) {
  return panda_virt_to_phys(cpu, virt_addr);
}

// we have this temporarily in callbacks.c -> to be moved here
/*
bool panda_load_external_plugin(const char *filename, const char *plugin_name, void *plugin_uuid, void *init_fn_ptr) {
    // don't load the same plugin twice
    uint32_t i;
    for (i=1; i<nb_panda_plugins_loaded; i++) {
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



// Taken from Avatar2's Configurable Machine - see hw/avatar/configurable_machine.c
void map_memory(char* name, uint64_t size, uint64_t address) {
    //const char * name; /// XXX const?
    MemoryRegion * ram;
    bool is_rom = false; // For now, only ram

    // Get memory from system. XXX may be unsafe to run too early (before machine_init)
    MemoryRegion *sysmem = get_system_memory();

    // Make memory region and initialize
    ram =  g_new(MemoryRegion, 1);
    g_assert(ram);

    if(!is_rom) {
        memory_region_init_ram(ram, NULL, name, size, &error_fatal);
    } else {
        memory_region_init_rom(ram, NULL, name, size, &error_fatal);
    }
    vmstate_register_ram(ram, NULL);

    printf("Adding memory region %s (size: 0x%"
           PRIx64 ") at address 0x%" PRIx64 "\n", name, size, address);

    // Add memory region to sysmem
    memory_region_add_subregion(sysmem, address, ram);
}
