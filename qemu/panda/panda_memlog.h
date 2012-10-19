#ifndef PANDA_MEMLOG_H
#define PANDA_MEMLOG_H

#include "inttypes.h"

//#ifdef CONFIG_LLVM_TRACE
void printloc(uintptr_t);
void printdynval(uintptr_t, int);
void printramaddr(uintptr_t, int);
//#endif

#endif

