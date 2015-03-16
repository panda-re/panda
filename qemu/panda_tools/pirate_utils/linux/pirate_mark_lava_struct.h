#ifndef __PIRATE_MARK_LAVA_STRUCT_H__
#define __PIRATE_MARK_LAVA_STRUCT_H__

#include "inttypes.h"

/*
 * Keep me in sync between PANDA and LAVA repos
 */

typedef struct pirate_mark_lava_struct {
    uint64_t filenamePtr;
    uint64_t lineNum;
    uint64_t astNodePtr;
} PirateMarkLavaInfo;

#endif

