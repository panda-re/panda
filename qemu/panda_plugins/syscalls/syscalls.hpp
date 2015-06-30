#ifndef __SYSCALLS_HPP
#define __SYSCALLS_HPP

#include "syscalls_common.hpp"
extern "C" {
//#include "syscalls_int.h"
void appendReturnPoint(ReturnPoint&& rp);
void registerExecPreCallback(pre_exec_callback_t callback);
}

extern void* syscalls_plugin_self;

#endif
