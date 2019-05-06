#ifndef __PANDA_API_H__
#define __PANDA_API_H__

#include <stdint.h>

int panda_pre(int argc, char **argv, char **envp);

int panda_init(int argc, char **argv, char **envp);

int panda_run(void);

int panda_finish(void);

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args);

int panda_replay(char *replay_name);

int panda_delvm(char *snapshot_name);

int panda_revert(char *snapshot_name);

int panda_snap(char *snapshot_name);

void panda_exit_emul_loop(void);

void panda_stop(void);
void panda_cont(void);

//int panda_load_external_plugin(const char* filename, const char *plugin_name, void *plugin_uuid, void* init_fn_ptr);
#endif
