#include <assert.h>

#include "vl.h"
#include "panda/panda_api.h"
#include "panda/plugin.h"

void qemu_rr_quit_timers(void);
//void qemu_cpu_kick(CPUState *cpu);

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

// initiate replay 
int panda_replay(char *replay_name) {
    rr_replay_requested = 1;
    rr_requested_name = strdup(replay_name);
    return 0;
//    return panda_run();
}
