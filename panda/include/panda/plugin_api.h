#ifndef PANDA_PLUGIN_API
#define PANDA_PLUGIN_API

#include "cpu.h"

inline CPUState* get_cpu(void) {
    // Violate the PANDA API - just give caller a handle to first_cpu
    // we should aim to remove these
    return first_cpu;
}

#endif
