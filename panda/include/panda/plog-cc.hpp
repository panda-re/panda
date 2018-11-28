/**
 *
 * Header file for C++ implementation of Pandalog.
 * See plog.c and plog.h for missing details
 * plog.c contains an overview of the log format
 * 8/19/17 Ray Wang 
 *
 */

#ifndef __PANDALOG_CC_H_
#define __PANDALOG_CC_H_

extern "C" {
#ifndef PLOG_READER
#include "panda/rr/rr_log.h"
#include "panda/common.h"
#endif

#include <zlib.h>
#include "panda/plog.h"
}

#include <stdio.h>
#include <iostream>
#include <memory>
#include <stdint.h>
#include "plog.pb.h"

#define PL_CURRENT_VERSION 2
// compression level
#define PL_Z_LEVEL 9
// 16 MB chunk
#define PL_CHUNKSIZE (1024 * 1024 * 16)
// header at most this many bytes
#define PL_HEADER_SIZE 128


typedef struct pandalog_header_struct {
    uint32_t version;     // version number
    uint64_t dir_pos;     // position in file of directory
    uint32_t chunk_size;  // chunk size
} PlHeader;

// directory mapping instructions to chunks in the outfile
// say el[0].instr = 1234
// that means chunk 0 contains all pandalog info for instructions 0..1234
// and say el[1].instr = 2468
// that means chunk 1 contains all .. for instr 12345 .. 2468
// additionally, the data for compressed chunk 0 is in the outfile
// from pos[0] .. pos[1]-1
struct PandalogCcDir {

    uint32_t num_chunks;       // max number of entries (chunks).  
                               // when writing, an overestimate.  when reading, this is num_chunks
    std::vector<uint64_t> instr;           // array of instruction counts.  instr[i] is start (first) instruction in chunk i
    std::vector<uint64_t> pos;             // array of file positions.      pos[i] is start file position for chunk i
    std::vector<uint64_t> num_entries;     // size of each chunk in number of pandalog entries
};


struct PandalogCcChunk {
    //pandalog_cc_chunk_struct() : entries(128){}

    uint32_t size;              // in bytes of a chunk
    uint32_t zsize;             // in bytes of a compressed chunk. 
    unsigned char *buf;         // uncompressed chunk data
    unsigned char *buf_p;       // pointer into uncompressed chunk (used while writing)
    unsigned char *zbuf;        // corresponding compressed chunk
    // these are used while writing to remember things needed for dir entry
    uint32_t start_instr;       // first instruction in current chunk 
    uint64_t start_pos;         // pos in file of start of current chunk
    // these are used while reading and contain current chunk data, expanded into pl entries
    std::vector<std::unique_ptr<panda::LogEntry>> entries;    // this will be array of entries in current chunk 
    uint32_t num_entries;       // size of that array 
    uint32_t max_num_entries;   // capacity of that array
    uint32_t ind_entry;         // index into array of entries
};

class PandaLog {
    PlMode mode;
    const char *filename;
    std::fstream *file;
    PandalogCcDir dir;
    PandalogCcChunk chunk;
    uint32_t chunk_num;

public:    
    //default constructor
    PandaLog(): mode(PL_MODE_UNKNOWN){
        mode = PL_MODE_UNKNOWN;
        chunk_num = 0;
    };

    // open pandalog for write with this uncompressed chunk size
    void open_write(const char *path, uint32_t chunk_size);

    void open_read(const char *path, PlMode mode);

    // open pandalog for reading in forward direction
    void open_read_fwd(const char *path);

    // open pandalog for reading in backward direction
    void open_read_bwd(const char *path);

    void open(const char *path, const char *mode);

    // close pandalog (all modes)
    int  close(void);

    void write_entry(std::unique_ptr<panda::LogEntry> entry);

    std::unique_ptr<panda::LogEntry> read_entry(void);

    // seek to the element in pandalog corresponding to this instr
    // only valid in read mode.  
    // if PL_MODE_READ_FWD then we seek to FIRST element in log for this instr
    // if PL_MODE_READ_BWD then we seek to LAST element in log for this instr
    void seek(uint64_t instr);

private: 
    //initializes some fields in the pandalog
    void create(uint32_t chunk_size);

    // Reads header, located at beginning of log
    PlHeader* read_header();

    // Write header to beginning of log
    void write_header(PlHeader *);

    //Read directory entries
    void read_dir();

    //Write directory entries
    void write_dir();

    // decompresses chunk and reads all entries into vector
    void unmarshall_chunk(uint32_t chunk_num);

    // Adds directory entry to list of directory entries. Does not write to log
    void add_dir_entry();

    //Zlib compresses and writes current chunk to log
    void write_current_chunk();

    // Finds index of entry with this instr number
    uint32_t find_ind(uint64_t instr, uint32_t lo, uint32_t high);

    //Finds chunk with this instr number
    uint32_t find_chunk(uint64_t instr, uint32_t lo, uint32_t high);
};

#endif
