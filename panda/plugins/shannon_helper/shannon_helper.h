#ifndef __SHANNON_HELPER_H
#define __SHANNON_HELPER_H

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

// required when building with C++11 and above as the files below do not include it
#include <functional>
#include "../callstack_instr/callstack_instr.h"
#include "../callstack_instr/callstack_instr_ext.h"

#endif
