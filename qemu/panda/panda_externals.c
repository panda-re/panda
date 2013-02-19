
#include "config.h"
#include "qemu-common.h"

#ifdef CONFIG_LLVM

extern CPUState *env;

#include "panda_externals.h"

// Get location of env, if needed in PANDA plugins
void *get_env(void){
    return &env;
}

#endif

