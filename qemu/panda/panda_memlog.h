#ifndef PANDA_MEMLOG_H
#define PANDA_MEMLOG_H

#include "inttypes.h"

void printloc(uintptr_t);
void printdynval(uintptr_t, int);
void printramaddr(uintptr_t, int);
void open_memlog(void);
void close_memlog(void);

#endif

