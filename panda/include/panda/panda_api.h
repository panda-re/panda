#ifndef __PANDA_API_H__
#define __PANDA_API_H__

#include <stdint.h>

void panda_init(int argc, char **argv, char **envp);

void panda_run(void);

void panda_finish(void);

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args);

#endif
