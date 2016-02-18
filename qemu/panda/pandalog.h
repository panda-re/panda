
#ifndef __PANDALOG_H_
#define __PANDALOG_H_

#include <zlib.h>

// directory mapping instructions to chunks in the chunksfile
// say el[0].instr = 1234
// that means chunk 0 contains all pandalog info for instructions 0..1234
// and say el[1].instr = 2468
// that means chunk 1 contains all .. for instr 12345 .. 2468
// additionally, the data for compressed chunk 0 is in the chunksfile
// from pos[0] .. pos[1]-1
typedef struct pandalog_dir_struct {
    uint32_t max_size;   // max number of entries
    uint64_t *instr;     // array of instruction counts.  instr[i] is last instruction in chunk i
    uint64_t *pos;       // array of file positions for start of chunk 
} PandalogDir;


typedef struct pandalog_struct {
    char *filename;       // filename of compressed log
    z_stream strm;        // zlib stream
    uint32_t chunk_size;  // in mb 
    uint32_t chunk;       // current chunk
    FILE *chunksfile;     // file to which we write compressed chunks
    PandalogDir dir;       
    uint8_t writep;       // 1 if log is open for write. 0 otherwise
} Pandalog;


#include "pandalog.pb-c.h"


// NB: there is only one pandalog
// so these fns dont return a Pandalog or pass one as a param
void pandalog_open(const char *path, const char *mode);
int  pandalog_close(void);

// write this element to pandpog.
// "asid", "pc", instruction count key/values
// b/c those will get added by this fn
void pandalog_write_entry(Panda__LogEntry *entry);

// read this element from pandalog.
// allocates memory, which caller will free
Panda__LogEntry *pandalog_read_entry(void);

// Must call this to free the entry returned by pandalog_read_entry
void pandalog_free_entry(Panda__LogEntry *entry);


extern int pandalog;

#endif

