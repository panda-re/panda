/*
  The Pandalog has three sections.

  Section 1: The header
  ---------------------
  Bytes 0 .. PL_HEADER_SIZE-1

  Currently, the header consists of just three ints

  u32 version      (a version number)
  u64 dir_pos     (file position of directory)
  u32 chunk_size  (size of an uncompressed chunk for this log)

  That's just 16 bytes.  Header is currently 128 so lots of room


  Section 2: The chunks
  ---------------------
  Byte PL_HEADER_SIZE .. dir_pos-1

  This is where the compressed chunks go.  As we write the pandalog,
  we fill a buffer with raw, uncompressed entries.  When we have gone
  over the chunk_size and done with all entries for an instruction, we
  compress that chunk of pandalog and write it to the file, keeping
  track in an array the file position of the start of each chunk.  The
  next compressed chunk data will go right after the previous
  compressed chunk data.

  CHUNKS section is just a sequence of compressed chunk data, varying
  in length.  Only way to tell where one compressed chunk starts and
  next ends is via the DIRECTORY.


  Section 3: The directory
  ------------------------
  Byte dir_pos .. end of file

  The directory goes here.  It contains a map which one can use to
  locate the compressed chunk corresponding to a particular
  instruction in the CHUNKS section of the pandalog file.

  uint32_t num_chunks               How many chunks are in CHUNKS sec
  uint64_t start_instr_chunk_0      First instruction in chunk 0
  uint64_t start_pos_chunk_0        File position of beginning of chunk 0
  uint64_t start_instr_chunk_1      ... for chunk 1
  uint64_t start_pos_chunk_1        ... for chunk 1
  ...
  uint64_t start_instr_chunk_n      ... for chunk n, where n == num_chunks-1
  uint64_t start_pos_chunk_n        ... for chunk n

*/

#ifndef PLOG_READER

#include "qemu/osdep.h"

#include "panda/common.h"
#include "panda/rr/rr_log.h"
#endif

#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "panda/plog.h"

// Externed functions that are wrappers around the C++ pandalog functions
extern void pandalog_write_packed(size_t entry_size, unsigned char* buf);
extern unsigned char* pandalog_read_packed(void);
extern void pandalog_cc_init_read(const char* path);
extern void pandalog_cc_init_write(const char* path);
extern void pandalog_cc_init_read_bwd(const char* path);
extern void pandalog_cc_seek(uint64_t);
extern void pandalog_cc_close(void);

void pandalog_open_read(const char *path, uint32_t pl_mode);


void pandalog_write_entry(Panda__LogEntry *entry) {
	// Pack this entry and pass it on to a C++ interface
		
	size_t packed_size = panda__log_entry__get_packed_size(entry);
	unsigned char* buf = malloc(packed_size);
	panda__log_entry__pack(entry, buf);

	pandalog_write_packed(packed_size, buf);
  free(buf);
}

void pandalog_open_read(const char *path, uint32_t pl_mode) {
	if (pl_mode == PL_MODE_READ_FWD) {
		pandalog_cc_init_read(path);
	} else if (pl_mode == PL_MODE_READ_BWD) {
		pandalog_cc_init_read_bwd(path);
	}
}

void pandalog_open_read_fwd(const char *path) {
	pandalog_cc_init_read(path);
}

void pandalog_open_read_bwd(const char *path) {
	pandalog_cc_init_read_bwd(path);
}

void pandalog_open(const char *path, const char *mode) {
    if (0==strcmp(mode, "w")) {
#ifndef PLOG_READER
        pandalog_cc_init_write((const char *) path);
#endif
    }
    if (0==strcmp(mode, "r")) {
        pandalog_cc_init_read(path);
    }
}

void pandalog_close(void) {
	pandalog_cc_close();
}


// Reads an entry from the pandalog in fwd or bwd direction, updating chunk and index 
// Returns NULL if all entries have been read 
Panda__LogEntry *pandalog_read_entry(void) {
	unsigned char* buf = pandalog_read_packed();
	if (!buf){
		return NULL;
	}
	size_t n = *((size_t *) buf);
	buf += sizeof(size_t);

	Panda__LogEntry *ple = panda__log_entry__unpack(NULL, n, buf);
	return ple;
}


void pandalog_seek(uint64_t instr) {
	pandalog_cc_seek(instr);
}

void pandalog_free_entry(Panda__LogEntry* entry){

}

