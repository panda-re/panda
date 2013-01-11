#ifndef __PANDA_STATS_H__
#define __PANDA_STATS__

#include "taint_processor.h"

void memplot(Shad *shad);
void bufplot(Shad *shad, uint64_t addr, int length);
void dump_taint_stats(Shad *shad);
void cleanup_taint_stats(void);

#endif

