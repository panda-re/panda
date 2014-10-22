#ifndef __SYSCALLS_HPP
#define __SYSCALLS_HPP

#include "syscalls_common.hpp"
extern "C" {
#include "syscalls_int.h"
}

extern void* syscalls_plugin_self;

#endif
