#ifndef __PANDA_API_H__
#define __PANDA_API_H__

// Functions considered part of the panda api that come from
// panda_api.c. Also some from common.c. Note that, while common.c has
// a header (common.h) it is unsuitable for use with cffi since it is
// larded with inline fns. Note that the real panda API for pypanda is
// really in the pypanda/include/panda_datatypes.h file

// NOTE: Pls read README before editing!

// from panda_api.c
int panda_init(int argc, char **argv, char **envp);
int panda_run(void);
void panda_set_library_mode(bool);
void panda_stop(int code);
void panda_cont(void);
void panda_start_pandalog(const char *name);
int panda_revert(char *snapshot_name);
void panda_reset(void);
int panda_snap(char *snapshot_name);
int panda_replay(char *replay_name);
int panda_finish(void);
bool panda_was_aborted(void);
target_ulong panda_virt_to_phys_external(CPUState *cpu, target_ulong virt_addr);

void panda_set_qemu_path(char* filepath);

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args);

void panda_register_callback_helper(void* plugin, panda_cb_type type, panda_cb* cb);
void panda_enable_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);
void panda_disable_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);

int rr_get_guest_instr_count_external(void);

int panda_virtual_memory_read_external(CPUState *env, target_ulong addr, char *buf, int len); // XXX: should we use hwaddr instead of target_ulong
int panda_virtual_memory_write_external(CPUState *env, target_ulong addr, char *buf, int len); // XXX: should we use hwaddr instead of target_ulong
int panda_physical_memory_read_external(hwaddr addr, uint8_t *buf, int len);
int panda_physical_memory_write_external(hwaddr addr, uint8_t *buf, int len);

target_ulong panda_current_sp_external(CPUState *cpu);
target_ulong panda_current_sp_masked_pagesize_external(CPUState *cpu, target_ulong pagesize);
bool panda_in_kernel_external(CPUState *cpu);

//void panda_monitor_run(char* buf, uint32_t len);
int panda_delvm(char *snapshot_name);

#ifdef PYPANDA

// Create a monitor for panda
void panda_init_monitor(void);

// Pass a message via the panda monitor. Create monitor if necessary'
// returns output string from monitor. Some commands may cause spinloops
char* panda_monitor_run(char* buf);

// Pass a message via the panda monitor. Create monitor if necessary'
// Does not return
void panda_monitor_run_async(char* buf);
#endif


// turns on taint
void panda_taint_enable(void) ;

// label this register
void panda_taint_label_reg(uint32_t reg_num, uint32_t label) ;

// returns true iff any byte in this register is tainted
bool panda_taint_check_reg(uint32_t reg_num, uint32_t size) ;


// Map a region of memory in the guest
//int panda_map_physical_mem(target_ulong addr, int len);

#endif
