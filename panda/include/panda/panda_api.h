#ifndef __PANDA_API_H__
#define __PANDA_API_H__

// Functions considered part of the panda api that come from
// panda_api.c. Also some from common.c. Note that, while common.c has
// a header (common.h) it is unsuitable for use with cffi since it is
// larded with inline fns. Note that the real panda API for pypanda is
// really in the pypanda/include/panda_datatypes.h file

// NOTE: Pls read README before editing!

extern bool panda_update_pc;
extern bool panda_use_memcb;
extern bool panda_tb_chaining;

// from common.c I think?
bool panda_flush_tb(void);
void panda_do_flush_tb(void);
void panda_enable_precise_pc(void);
void panda_disable_precise_pc(void);
void panda_enable_memcb(void);
void panda_disable_memcb(void);
void panda_enable_tb_chaining(void);
void panda_disable_tb_chaining(void);
void panda_enable_llvm(void);
void panda_disable_llvm(void);
void panda_enable_llvm_helpers(void);
void panda_disable_llvm_helpers(void);
void panda_memsavep(FILE *f);

// from panda_api.c
int panda_pre(int argc, char **argv, char **envp);
int panda_init(int argc, char **argv, char **envp);
int panda_run(void);
void panda_stop(void);
void panda_cont(void);
int panda_revert(char *snapshot_name);
int panda_snap(char *snapshot_name);
int panda_replay(char *replay_name);
int panda_finish(void);


void panda_set_qemu_path(char* filepath);

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args);

void panda_register_callback_helper(void* plugin, panda_cb_type type, panda_cb* cb);
void panda_enable_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);
void panda_disable_callback_helper(void *plugin, panda_cb_type, panda_cb* cb);

int rr_get_guest_instr_count_external(void);

int panda_virtual_memory_read_external(CPUState *env, target_ulong addr, char *buf, int len);
int panda_virtual_memory_write_external(CPUState *env, target_ulong addr, char *buf, int len);

target_ulong panda_current_sp_external(CPUState *cpu);
target_ulong panda_current_sp_masked_pagesize_external(CPUState *cpu, target_ulong pagesize);
bool panda_in_kernel_external(CPUState *cpu);

//void panda_monitor_run(char* buf, uint32_t len);
int panda_delvm(char *snapshot_name);
void panda_exit_emul_loop(void);



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

#endif
