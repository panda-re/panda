/**
 *
 * Header file for C++ version of Pandalog. Mostly identical to C version in plog.c
 * See plog.c and plog.h for missing details
 * plog.c contains an overview of the log format
 * 8/19/17 Ray Wang 
 *
 */

#ifndef __PANDALOG_CC_H_
#define __PANDALOG_CC_H_

extern "C" {

#include "panda/rr/rr_log.h"
#include <zlib.h>
#include "panda/common.h"
}

#include <stdio.h>
#include <iostream>
#include <memory>
#include <stdint.h>
#include "panda/plog.pb.h"
#include "panda/plog.h"

#define PL_CURRENT_VERSION 2
// compression level
#define PL_Z_LEVEL 9
// 16 MB chunk
#define PL_CHUNKSIZE (1024 * 1024 * 16)
// header at most this many bytes
#define PL_HEADER_SIZE 128


typedef struct pandalog_cc_dir_struct {
    uint32_t max_chunks;       // max number of entries (chunks).  
                               // when writing, an overestimate.  when reading, this is num_chunks
    std::vector<uint64_t> instr;           // array of instruction counts.  instr[i] is start (first) instruction in chunk i
    std::vector<uint64_t> pos;             // array of file positions.      pos[i] is start file position for chunk i
    std::vector<uint64_t> num_entries;     // size of each chunk in number of pandalog entries
} PandalogCcDir;


typedef struct pandalog_cc_chunk_struct {
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
} PandalogCcChunk;

class PandaLog {
    PlMode mode;
    const char *filename;
    std::fstream *file;
    PandalogCcDir dir;
    PandalogCcChunk chunk;
    uint32_t chunk_num;

public:    
    //default constructor
    PandaLog(){
        mode = PL_MODE_UNKNOWN;
        chunk_num = 0;
    };

    // open pandalog for write with this uncompressed chunk size
    void pandalog_open_write(const char *path, uint32_t chunk_size);

    void pandalog_open_read(const char *path, PlMode mode);

    // open pandalog for reading in forward direction
    void pandalog_open_read_fwd(const char *path);

    // open pandalog for reading in backward direction
    void pandalog_open_read_bwd(const char *path);

    void pandalog_open(const char *path, const char *mode);

    // close pandalog (all modes)
    int  pandalog_close(void);

    void pandalog_write_entry(std::unique_ptr<panda::LogEntry> entry);

    std::unique_ptr<panda::LogEntry> pandalog_read_entry(void);

    void pandalog_seek(uint64_t instr);

private: 
    //initializes some fields in the pandalog
    void pandalog_create(uint32_t chunk_size);

    // Reads header, located at beginning of log
    PlHeader* pandalog_read_header();

    // Write header to beginning of log
    void write_header(PlHeader *);

    //Read directory entries
    void pandalog_read_dir();

    //Write directory entries
    void pandalog_write_dir();

    // decompresses chunk and reads all entries into vector
    void unmarshall_chunk(uint32_t chunk_num);

    // Adds directory entry to list of directory entries. Does not write to log
    void add_dir_entry(uint32_t chunk_num);

    //Zlib compresses and writes current chunk to log
    void write_current_chunk();

    // Finds index of entry with this instr number
    uint32_t find_ind(uint64_t instr, uint32_t lo, uint32_t high);

    //Finds chunk with this instr number
    uint32_t find_chunk(uint64_t instr, uint32_t lo, uint32_t high);

};

PandaLog globalLog;

#endif
