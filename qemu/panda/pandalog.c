
#ifndef PANDALOG_READER
#include "panda_common.h"
#include "rr_log.h"
#endif


#include "pandalog.pb-c.h"
#include "pandalog.h"
#include "pandalog_print.h"
#include <zlib.h>
#include <stdlib.h>




// compression level
#define PL_Z_LEVEL 9
// 16 MB chunk
#define PL_CHUNKSIZE (1024 * 1024 * 16)


Pandalog *thePandalog = NULL;


unsigned char *chunk_buf = 0;
unsigned char *chunk_buf_p = 0;

void grow_pandalog_dir(uint32_t new_size);
void add_dir_entry(uint32_t chunk, uint64_t file_pos, uint64_t last_instr);
void write_current_chunk(void);
void check_write(size_t n);
void pandalog_open_write(const char *path);
void pandalog_open(const char *path, const char *mode);
int  pandalog_close(void);
void pandalog_write_entry(Panda__LogEntry *entry);


// grow pandalog dir to be this new bigger size
void grow_pandalog_dir(uint32_t new_size) {
    assert (new_size > thePandalog->dir.max_size);
    thePandalog->dir.max_size = new_size;
    thePandalog->dir.instr = (uint64_t *) realloc(thePandalog->dir.instr, sizeof(uint64_t) * new_size);
    thePandalog->dir.pos = (uint64_t *) realloc(thePandalog->dir.pos, sizeof(uint64_t) * new_size);
}

// add dir entry for this chunk
// last_instr is last instr in this chunk
void add_dir_entry(uint32_t chunk, uint64_t file_pos, uint64_t last_instr) {
    if (chunk >= thePandalog->dir.max_size) {
        grow_pandalog_dir(thePandalog->dir.max_size * 1.5);
    }
    assert (chunk <= thePandalog->dir.max_size);
    thePandalog->dir.instr[chunk] = last_instr;
    thePandalog->dir.pos[chunk] = file_pos;
}

// compress current chunk and write it to chunksfile,
// also updating directory 
void write_current_chunk(void) {
    // uncompressed chunk size
    uint32_t cs = chunk_buf_p - chunk_buf;
    if (cs == 0) return;
    // compress pandalog chunk
    thePandalog->strm.avail_in = cs;
    thePandalog->strm.next_in = chunk_buf;
    int ret = deflate(&(thePandalog->strm), Z_NO_FLUSH);
    assert(ret != Z_STREAM_ERROR); 
    assert(thePandalog->strm.avail_in == 0);
    // size of compressed chunk
    uint32_t css = thePandalog->strm.avail_out;
    assert(css > 0);
    assert(cs >= css);
    printf ("writing chunk %d of pandalog %d / %d = %.2f compression\n",
            thePandalog->chunk, cs, css, ((float) cs) / ((float) css)); 
    // position in chunksfile of start of this chunk
    uint64_t pos = ftell(thePandalog->chunksfile);
    fwrite(chunk_buf, 1, css, thePandalog->chunksfile);
    add_dir_entry(thePandalog->chunk, pos, rr_get_guest_instr_count ());
}


// we need to write n bytes to chunk_buf.  will it fit?
void check_write(size_t n) {
    // initial alloc
    if (chunk_buf == 0) {
        // NB: malloc chunk a little big since we need to maintain
        // the invariant that all log entries for an instruction reside in same
        // chunk.  this should be big enough...
        chunk_buf = (unsigned char *) malloc(thePandalog->chunk_size * 1.25);
        chunk_buf_p = chunk_buf;
        assert(n < thePandalog->chunk_size);
        return;
    }
    if (chunk_buf_p + n < chunk_buf + thePandalog->chunk_size) {
        // fine to write -- it fits
        return;
    }
    // write won't fit in current chunk.  
    // we need to move on to next chunk first
    write_current_chunk();
    // rewind chunk buf and inc chunk #
    chunk_buf_p = chunk_buf;
    thePandalog->chunk ++;
}




// open pandalog for write
// path is the chunks file
// path + '.dir' is the directory
void pandalog_open_write(const char *path) {
    assert (thePandalog == NULL);
    thePandalog = (Pandalog *) malloc(sizeof(Pandalog));
    thePandalog->writep = 1;
    thePandalog->filename = strdup(path);
    thePandalog->chunksfile = fopen(path, "w");
    thePandalog->strm.zalloc = Z_NULL;
    thePandalog->strm.zfree = Z_NULL;
    thePandalog->strm.opaque = Z_NULL;
    int ret = deflateInit(&thePandalog->strm, PL_Z_LEVEL);
    assert (ret == Z_OK);
    thePandalog->chunk_size = PL_CHUNKSIZE;
    thePandalog->chunk = 0;   
    // NB: dir will grow later if we need more than 128 chunks
    thePandalog->dir.max_size = 128;
    thePandalog->dir.instr = (uint64_t *) malloc(sizeof(uint64_t) * thePandalog->dir.max_size);
    thePandalog->dir.pos = (uint64_t *) malloc(sizeof(uint64_t) * thePandalog->dir.max_size);   
}


void pandalog_open(const char *path, const char *mode) {
    if (0 == strcmp(mode, "w")) {
        pandalog_open_write(path);
    }
    else {
        printf ("pandalog_open mode=[%s] not supported\n", mode);
        abort();
    }
}


int  pandalog_close(void) {
    if (thePandalog->writep) {
        // finish current chunk & close chunksfile 
        write_current_chunk();
        // write directory 
        char *dirfilename = (char*) malloc(strlen(thePandalog->filename)+4);
        dirfilename[0] = '\0';
        strcat(dirfilename, thePandalog->filename);
        strcat(dirfilename, ".dir");
        FILE *dfp = fopen(dirfilename, "w");
        PandalogDir *dir = &(thePandalog->dir);
        uint32_t num_chunks = thePandalog->chunk + 1;
        // note: this is actual dir size.  max_size generally bigger
        fwrite(&(num_chunks), sizeof(num_chunks), 1, dfp);
        uint32_t i;
        for (i=0; i<=num_chunks; i++) {
            fwrite(&(dir->instr[i]), sizeof(dir->instr[i]), 1, dfp);
            fwrite(&(dir->pos[i]), sizeof(dir->pos[i]), 1, dfp);
        }
        fclose(dfp);
    }
    fclose(thePandalog->chunksfile);
    return 0;
}
extern int panda_in_main_loop;


uint64_t instr_last_entry = 0;

#ifndef PANDALOG_READER
void pandalog_write_entry(Panda__LogEntry *entry) {
    // fill in required fields. 
    if (panda_in_main_loop) {
        entry->pc = panda_current_pc(cpu_single_env);
        entry->instr = rr_get_guest_instr_count ();
    }
    else {        
        entry->pc = -1;
        entry->instr = -1;
    }
    size_t n = panda__log_entry__get_packed_size(entry);
    // possibly compress and write current chunk
    // but dont do so if it would spread log entries for same instruction between chunks
    // invariant: all log entries for an instruction belong in a single chunk
    if (instr_last_entry != entry->instr) {
        check_write(n+4);
    }
    // write size of log entry first
    *((uint32_t *) chunk_buf_p) = n;
    chunk_buf_p += sizeof(uint32_t);
    // and then the entry itself (packed)
    panda__log_entry__pack(entry, chunk_buf_p);
    instr_last_entry = entry->instr;
}
#endif

/*
Panda__LogEntry *pandalog_read_entry(void) {
    // read the size of the log entry
    size_t n,nbr;
    nbr = gzread(pandalog_file, (void *) &n, sizeof(n));
    if (nbr == 0) {
        return NULL;
    }
    resize_pandalog(n);
    // and then read the entry iself
    gzread(pandalog_file, chunk_buf, n);
    // and unpack it
    Panda__LogEntry *ple = panda__log_entry__unpack(NULL, n, chunk_buf);                                             
    if (ple == NULL) {
	return (Panda__LogEntry *)1; //yay special values
    }
    return ple;
}
*/

void pandalog_free_entry(Panda__LogEntry *entry) {    
    panda__log_entry__free_unpacked(entry, NULL);
}



