
#ifndef __PANDALOG_H_
#define __PANDALOG_H_

#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include "pandalog.pb-c.h"

#define PL_CURRENT_VERSION 2
// compression level
#define PL_Z_LEVEL 9
// 16 MB chunk
#define PL_CHUNKSIZE (1024 * 1024 * 16)
// header at most this many bytes
#define PL_HEADER_SIZE 128

// this is how much bigger than chunk size we'll alloc buf and zbuf
#define SLACK_MULT (1.25)

typedef enum {
    PL_MODE_WRITE,
    PL_MODE_READ_FWD,
    PL_MODE_READ_BWD,
    PL_MODE_UNKNOWN
} PlMode;

typedef struct pandalog_header_struct {
    uint32_t version;     // version number
    uint64_t dir_pos;     // position in file of directory
    uint32_t chunk_size;  // chunk size
} PlHeader;

typedef struct instr_interval_struct {
    uint64_t start;
    uint64_t end;
} Interval;

// directory mapping instructions to chunks in the outfile
// say el[0].instr = 1234
// that means chunk 0 contains all pandalog info for instructions 0..1234
// and say el[1].instr = 2468
// that means chunk 1 contains all .. for instr 12345 .. 2468
// additionally, the data for compressed chunk 0 is in the outfile
// from pos[0] .. pos[1]-1
typedef struct pandalog_dir_struct {
    uint32_t max_chunks;       // max number of entries (chunks).  
                               // when writing, an overestimate.  when reading, this is num_chunks
    uint64_t *instr;           // array of instruction counts.  instr[i] is start (first) instruction in chunk i
    uint64_t *pos;             // array of file positions.      pos[i] is start file position for chunk i
    uint64_t *num_entries;     // size of each chunk in number of pandalog entries
} PandalogDir;

typedef struct pandalog_chunk_struct {
    uint32_t size;              // in bytes of a chunk
    uint32_t zsize;             // in bytes of a compressed chunk. 
    unsigned char *buf;         // uncompressed chunk data
    unsigned char *buf_p;       // pointer into uncompressed chunk (used while writing)
    unsigned char *zbuf;        // corresponding compressed chunk
    // these are used while writing to remember things needed for dir entry
    uint32_t start_instr;       // first instruction in current chunk 
    uint64_t start_pos;         // pos in file of start of current chunk
    // these are used while reading and contain current chunk data, expanded into pl entries
    Panda__LogEntry **entry;    // this will be array of entries in current chunk 
    uint32_t num_entries;       // size of that array 
    uint32_t max_num_entries;   // capacity of that array
    uint32_t ind_entry;         // index into array of entries
} PandalogChunk;

typedef struct pandalog_struct {
    PlMode mode;                // write, read fwd, read bwd
    char *filename;             // filename of compressed log
    FILE *file;                 // file to which we write compressed chunked pandalog
    PandalogDir dir;            // chunk directory
    PandalogChunk chunk;        // current chunk
    uint32_t chunk_num;         // current chunk number
} Pandalog;

// open pandalog for write with this uncompressed chunk size
void pandalog_open_write(const char *path, uint32_t chunk_size);

// open pandalog for reading in forward direction
void pandalog_open_read_fwd(const char *path);

// open pandalog for reading in backward direction
void pandalog_open_read_bwd(const char *path);

void pandalog_open(const char *path, const char *mode);

// close pandalog (all modes)
int  pandalog_close(void);

// write this element to pandpog.
// "asid", "pc", instruction count key/values
// b/c those will get added by this fn
void pandalog_write_entry(Panda__LogEntry *entry);

// read next element from pandalog.
// allocates memory, which caller will free
// nb depending on thePandalog->mode this could represent 
// fwd or bwd motion in the log
Panda__LogEntry *pandalog_read_entry(void);

// seek to the element in pandalog corresponding to this instr
// only valid in read mode.  
// if PL_MODE_READ_FWD then we seek to FIRST element in log for this instr
// if PL_MODE_READ_BWD then we seek to LAST element in log for this instr
void pandalog_seek(uint64_t instr);

// Must call this to free the entry returned by pandalog_read_entry
void pandalog_free_entry(Panda__LogEntry *entry);

extern int pandalog;

#endif

