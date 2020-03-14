#ifndef __PANDA_API_H__
#define __PANDA_API_H__

// Functions and variables exclusively used by API consumers.
// Nothing in core-panda should need to include this file

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// from panda_api.c
int panda_init(int argc, char **argv, char **envp);
int panda_run(void);
void panda_set_library_mode(bool);
void panda_stop(int code);
void panda_cont(void);
int panda_delvm(char *snapshot_name);
void panda_start_pandalog(const char *name);
int panda_revert(char *snapshot_name);
void panda_reset(void);
int panda_snap(char *snapshot_name);
int panda_finish(void);
bool panda_was_aborted(void);

void panda_set_qemu_path(char* filepath);

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args);

void panda_register_callback_helper(void* plugin, panda_cb_type type, panda_cb* cb);
void panda_enable_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);
void panda_disable_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);

int rr_get_guest_instr_count_external(void);

int panda_virtual_memory_read_external(CPUState *env, target_ulong addr, char *buf, int len);
int panda_virtual_memory_write_external(CPUState *env, target_ulong addr, char *buf, int len);
int panda_physical_memory_read_external(hwaddr addr, uint8_t *buf, int len);
int panda_physical_memory_write_external(hwaddr addr, uint8_t *buf, int len);

bool panda_in_kernel_external(CPUState *cpu);
target_ulong panda_current_sp_external(CPUState *cpu);
target_ulong panda_current_sp_masked_pagesize_external(CPUState *cpu, target_ulong pagesize);
target_ulong panda_virt_to_phys_external(CPUState *cpu, target_ulong virt_addr);

void map_memory(char* name, uint64_t size, uint64_t address);

// REDEFINITIONS below here from monitor.h

// Create a monitor for panda
void panda_init_monitor(void); // Redefinition from monitor.h

// Pass a message via the panda monitor. Create monitor if necessary'
// returns output string from monitor. Some commands may cause spinloops
char* panda_monitor_run(char* buf);// Redefinition from monitor.h

// Map a region of memory in the guest. WIP
//int panda_map_physical_mem(target_ulong addr, int len);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif
