#include <assert.h>

#include "vl.h"
#include "panda/panda_api.h"
#include "panda/plugin.h"

void panda_init(int argc, char **argv, char **envp) {
    int rv = main_aux(argc, argv, envp, PANDA_INIT);
    assert (rv == 0);
}

void panda_run(void) {
    int rv = main_aux(0, 0, 0, PANDA_RUN);
    assert (rv == 0);
}

void panda_finish(void) {
    int rv = main_aux(0, 0, 0, PANDA_FINISH);
    assert (rv = 0);
}

int panda_init_plugin(char *plugin_name, char **plugin_args, uint32_t num_args) {
    for (uint32_t i=0; i<num_args; i++) 
        panda_add_arg(plugin_name, plugin_args[i]);
    char *plugin_path = panda_plugin_path((const char *) plugin_name);
    return panda_load_plugin(plugin_path, plugin_name);
}




