
#ifndef PANDALOG_READER
#include "panda_common.h"
#include "rr_log.h"
#endif


#include "pandalog.pb-c.h"
#include "pandalog.h"
#include "pandalog_print.h"
#include <zlib.h>
#include <stdlib.h>




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


Pandalog pandalog;


unsigned char *chunk_buf = 0;
unsigned char *chunk_buf_p = 0;


// grow pandalog dir to be this new bigger size
void grow_pandalog_dir(uint32_t new_size) {
    assert (new_size > pandalog.dir.max_size);
    pandalog.dir.max_size = new_size;
    pandalog.dir.instr = (uint64_t *) realloc(pandalog.dir.instr, sizeof(uint64_t) * new_size);
    pandalog.dir.pos = (uint64_t *) realloc(pandalog.dir.pos, sizeof(uint64_t) * new_size);
}

// add dir entry for this chunk
// last_instr is last instr in this chunk
void add_dir_entry(uint32_t chunk, uint64_t file_pos, uint64_t last_instr) {
    if (chunk >= pandalog.dir.max_size) {
        grow_pandalog_dir(pandalog.dir.size * 1.5);
    }
    assert (chunk <= pandalog.dir.size);
    pandalog.dir.instr[chunk] = last_instr;
    pandalog.dir.pos[chunk] = file_pos;
}

// compress current chunk and write it to chunksfile,
// also updating directory 
void write_current_chunk() {
    // uncompressed chunk size
    uint32_t cs = chunk_buf_p - chunk_buf;
    if (cs == 0) return;
    // compress pandalog chunk
    pandalog.strm.avail_in = cs;
    pandalog.strm.next_in = chunk_buf;
    int ret = deflate(&(pandalog.strm), Z_NO_FLUSH);
    assert(ret != Z_STREAM_ERROR); 
    assert(pandalog.strm.avail_in == 0);
    // size of compressed chunk
    uint32_t css = pandalog.strm.avail_out;
    assert(css > 0);
    assert(cs >= css);
    printf ("writing chunk %d of pandalog %d / %d = %.2f compression\n",
            pandalog.chunk, cs, css, ((float) cs) / ((float) css)); 
    // position in chunksfile of start of this chunk
    uint64_t pos = ftell(pandalog.chunksfile);
    fwrite(chunk_buf, 1, css, pandalog.chunksfile);
    add_dir_entry(pandalog.chunk, pos, rr_get_guest_instr_count ());
}


// we need to write n bytes to chunk_buf.  will it fit?
void check_write(size_t n) {
    // initial alloc
    if (chunk_buf == 0) {
        // NB: malloc chunk a little big since we need to maintain
        // the invariant that all log entries for an instruction reside in same
        // chunk.  this should be big enough...
        chunk_buf = (unsigned char *) malloc(pandalog.chunk_size * 1.25);
        chunk_buf_p = chunk_buf;
        assert(n < pandalog.chunk_size);
        return;
    }
    if (chunk_buf_p + n < chunk_buf + pandalog.chunk_size) {
        // fine to write -- it fits
        return;
    }
    // write won't fit in current chunk.  
    // we need to move on to next chunk first
    write_current_chunk();
    // rewind chunk buf and inc chunk #
    chunk_buf_p = chunk_buf;
    pandalog.chunk ++;
}



// compression level
#define PL_Z_LEVEL 9
// 16 MB chunk
#define PL_CHUNKSIZE (1024 * 1024 * 16)


// open pandalog for write
// path is the chunks file
// path + '.dir' is the directory
void pandalog_open_write(const char *path) {
    pandalog.writep = 1;
    pandalog.filename = path;
    pandalog.chunksfile = fopen(path, "w");
    pandalog.strm.zalloc = Z_NULL;
    pandalog.strm.zfree = Z_NULL;
    pandalog.strm.opaque = Z_NULL;
    int ret = deflateInit(&pandalog.strm, PL_Z_LEVEL);
    assert (ret == Z_OK);
    pandalog.chunk_size = PL_CHUNKSIZE;
    pandalog.chunk = 0;   
    // NB: dir will grow later if we need more than 128 chunks
    pandalog.dir.max_size = 128;
    pandalog.dir.size = 0;
    pandalog.dir.instr = (uint64_t *) malloc(sizeof(uint64_t) * pandalog.dir.max_size);
    pandalog.dir.pos = (uint64_t *) malloc(sizeof(uint64_t) * pandalog.dir.max_size);   
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
    if (pandalog.writep) {
        // finish current chunk & close chunksfile 
        write_current_chunk();
        // write directory 
        uint32_t n = strlen(pandalog.filename);
        char *dirfilename = (char*) malloc(strlen(pandalog.filename)+4);
        dirfilename[0] = '\0';
        strcat(dirfilename, pandalog.filename);
        strcat(dirfilename, ".dir");
        FILE *dfp = fopen(dirfilename, "w");
        PandalogDir *dir = &(pandalog.dir);
        fwrite(&(dir->size), sizeof(dir->size), 1, dfp);
        uint32_t i;
        for (i=0; i<dir->size; i++) {
            fwrite(&(dir->el[i].instr), sizeof(dir->el[i].start), 1, dfp);
            fwrite(&(dir->pos[i]), sizeof(dir->pos[i]), 1, dfp);
        }
        fclose(dfp);
    }
    fclose(pandalog.chunksfile);
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
    if (instr_last_entry != entr->instr) {
        check_write(n+4);
    }
    // write size of log entry first
    *((uint32_t *) chunk_buf_p) = n;
    chunk_buf_p += sizeof(uin32_t);
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



