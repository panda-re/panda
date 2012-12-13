#ifndef __LAREDO_INSTRUMENTATION_H__
#define __LAREDO_INSTRUMENTATION_H__

#include "taint_processor.h"

void memplot(Shad *shad);
void bufplot(Shad *shad, uint64_t addr, int length);
void dump_taint_stats(Shad *shad);
void cleanup_taint_stats();

#endif

