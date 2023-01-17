/**
 * Header file for C wrapper around C++ pandalog
 * These functions are now just shells that invoke the C++ implementation
 * They exist to maintain compatibility with plugins and tools written in C
 *
 * 8/30/17 Ray Wang
 *
 *
 * NOTE: There is only ONE pandalog open for read / write at a time.
 *       which is why closing does not need to have a handle, since
 *       that is in a global.
 */

#ifndef __PANDALOG_H_
#define __PANDALOG_H_

#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include "plog.pb-c.h"

/**
 * typedef enum PLMode - The pandalog mode.
 * @PL_MODE_WRITE: open for write.
 * @PL_MODE_READ_FWD: open for read, forwards direction
 * @PL_MODE_READ_BWD: open for read, backwards direction
 * @PL_MODE_UNKNOWN: not sure
*/

typedef enum {
    PL_MODE_WRITE,
    PL_MODE_READ_FWD,
    PL_MODE_READ_BWD,
    PL_MODE_UNKNOWN
} PlMode;

/**
 * pandalog_open_write() - Open the pandalog for write.
 * @filename: Filename for pandalog that will be created.
 * @chunk_size: Chunk size in bytes.
 * 
 * Open the pandalog for writing, using this filename and chunk
 * size. Chunk size might be changed to improve performance.
 */
void pandalog_open_write(const char *filename, uint32_t chunk_size);

/**  
 * pandalog_open_read_fwd() - Open the pandalog for reading forwards.
 * @filename: Filename for pandalog that we will be reading.
 *
 * Open the pandalog for reading in forwards direction. This is the
 * same direction as time flows.
 */
void pandalog_open_read_fwd(const char *filename);

/** 
 * pandalog_open_read_bwd() - Open the pandalog for reading backwards.
 * @filename: Filename for pandalog that we will be reading.
 *
 * Pandalog opened for reading in backwards direction. This is the
 * opposite direction as time flows, and so can be useful for analyses
 * that work backwards from the end of an execution trace, such as a
 * backwards dynamic slice.
 *
 */
void pandalog_open_read_bwd(const char *filename);


/**
 * pandalog_open() - Open the pandalog for read or write.
 * @filename: Filename for the pandalog.
 * @mode: Either "r" or "w".
 *
 * Pandalog opened for reading or writing (thus in forwards
 * direction, i.e., the same direction as time flows).
 */ 
void pandalog_open(const char *filename, const char *mode);


/**
 * pandalog_close() - Close the pandalog for read or write.
 *
 * Pandalog flushed and closed (regardless of direction or read/write
 * mode). 
 */ 
void pandalog_close(void);

/**
 * pandalog_write_entry() - Write an entry to the pandalog.
 * @entry: Pointer to the entry. 
 *
 * XXX: Tell reader where to look to know what Panda__LogEntry looks like.
 */
void pandalog_write_entry(Panda__LogEntry *entry);

/**
 * pandalog_read_entry() - Read an entry from the pandalog.
 * 
 * Return: pointer to allocated and populated pandalog entry.
 */
Panda__LogEntry *pandalog_read_entry(void);

/**
 * pandalog_seek() - Fast forward or rewind to instruction in pandalog.
 * @instr: The instruction count to seek to.
 * 
 */
void pandalog_seek(uint64_t instr);

/**
 * pandalog_free_entry() - Free memory for this entry.
 * @entry: Pointer to the entry.
 * 
 * Since pandalog_read_entry allocates, caller will need to free the
 * memory for the entry.
 */
void pandalog_free_entry(Panda__LogEntry *entry);


extern int pandalog;

#endif

