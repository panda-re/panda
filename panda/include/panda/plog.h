/**
 * Header file for C wrapper around C++ pandalog
 * These functions are now just shells that invoke the C++ implementation
 * They exist to maintain compatibility with plugins and tools written in C
 *
 * 8/30/17 Ray Wang
 *
 */

#ifndef __PANDALOG_H_
#define __PANDALOG_H_

#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include "plog.pb-c.h"

typedef enum {
    PL_MODE_WRITE,
    PL_MODE_READ_FWD,
    PL_MODE_READ_BWD,
    PL_MODE_UNKNOWN
} PlMode;

// open pandalog for write with this uncompressed chunk size
void pandalog_open_write(const char *path, uint32_t chunk_size);

// open pandalog for reading in forward direction
void pandalog_open_read_fwd(const char *path);

// open pandalog for reading in backward direction
void pandalog_open_read_bwd(const char *path);

void pandalog_open(const char *path, const char *mode);

// close pandalog (all modes)
void pandalog_close(void);

void pandalog_write_entry(Panda__LogEntry *entry);

Panda__LogEntry *pandalog_read_entry(void);

void pandalog_seek(uint64_t instr);

void pandalog_free_entry(Panda__LogEntry *entry);

extern int pandalog;

#endif

